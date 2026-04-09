package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"

	pb "KernelHarbor/cmd/analysis/pb"
)

var (
	grpcServer           *grpc.Server
	autoAnalyzeByDefault = true
)

func startGrpcServer(addr string, wg *sync.WaitGroup) {
	defer wg.Done()

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer = grpc.NewServer()
	pb.RegisterAgentServiceServer(grpcServer, &grpcHandler{})

	log.Printf("gRPC server listening on %s", addr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Printf("gRPC server error: %v", err)
	}
}

type grpcHandler struct {
	pb.UnimplementedAgentServiceServer
}

func (h *grpcHandler) Ingest(ctx context.Context, req *pb.IngestRequest) (*pb.IngestResponse, error) {
	for _, e := range req.Events {
		event := convertPbToEvent(e)

		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now()
		}
		if event.EventID == "" {
			event.EventID = generateEventID()
		}

		query := event.CommandLine
		if query == "" {
			query = event.FilePath
		}
		if query == "" {
			query = event.RemoteAddr
		}

		verdict := "benign"
		confidence := float32(0.0)

		if autoAnalyzeByDefault && query != "" {
			if hasSuspiciousPattern(query) {
				verdict = "suspicious"
				confidence = 0.7
			} else {
				confidence = 0.3
			}
		}

		log.Printf("Received event: %s [%s] PID=%d CMD=%s | VERDICT=%s CONFIDENCE=%.2f",
			event.EventType, event.EventID, event.ProcessID, event.CommandLine, verdict, confidence)

		processor.Submit(event)
	}

	return &pb.IngestResponse{Accepted: uint32(len(req.Events))}, nil
}

func (h *grpcHandler) Analyze(ctx context.Context, req *pb.AnalysisRequest) (*pb.AnalysisResponse, error) {
	query := req.Query
	if query == "" {
		query = "ls"
	}

	verdict := "benign"
	confidence := float32(0.5)

	if hasSuspiciousPattern(query) {
		verdict = "suspicious"
		confidence = 0.7
	}

	return &pb.AnalysisResponse{
		Verdict:    verdict,
		Confidence: confidence,
		Summary:    fmt.Sprintf("Analyzed command: %s", query),
	}, nil
}

func hasSuspiciousPattern(cmd string) bool {
	if cmd == "" {
		return false
	}

	suspiciousPatterns := []string{
		`curl\s+[^\s]+\s*\|`,    // curl piped to another command
		`curl\s+[^\s]+\s*>\s*/`, // curl redirect to file
		`wget\s+-[OQAq]`,        // wget with output flags
		`wget\s+[^\s]+\s*\|`,    // wget piped
		`wget\s+[^\s]+\s*>\s*/`, // wget redirect
		`bash\s+-i`,             // interactive bash
		`sh\s+-i`,               // interactive sh
		`nc\s+-[lv]`,            // netcat listen/verbose
		`nc\s+[0-9]`,            // netcat with target
		`netcat\s+`,             // netcat
		`socat\s+`,              // socat
		`base64\s+-d`,           // base64 decode
		`powershell`,            // powershell
		`python.*socket`,        // python socket
		`python.*subprocess`,    // python subprocess
		`python.*-c\s+`,         // python one-liner
		`/bin/(ba)?sh\s+-c`,     // shell -c
	}

	for _, pattern := range suspiciousPatterns {
		matched, _ := regexp.MatchString(pattern, cmd)
		if matched {
			return true
		}
	}

	dangerousExtensions := []string{`\.sh$`, `\.bash$`, `\.ps1$`}
	for _, ext := range dangerousExtensions {
		matched, _ := regexp.MatchString(ext, cmd)
		if matched {
			return true
		}
	}

	return false
}

func convertPbToEvent(e *pb.Event) Event {
	return Event{
		Timestamp:   parseTimestamp(e.Timestamp),
		HostName:    e.HostName,
		EventType:   e.EventType,
		EventID:     e.EventId,
		ProcessID:   e.ProcessId,
		ImagePath:   e.ImagePath,
		CommandLine: e.CommandLine,
		FilePath:    e.FilePath,
		FileFlags:   strconv.FormatInt(int64(e.Flags), 10),
		FileMode:    e.Mode,
		RemoteAddr:  e.RemoteAddr,
		RemotePort:  uint16(e.RemotePort),
		LocalAddr:   e.LocalAddr,
		LocalPort:   uint16(e.LocalPort),
	}
}

func parseTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
