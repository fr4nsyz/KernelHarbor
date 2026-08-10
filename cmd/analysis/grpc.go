package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "KernelHarbor/cmd/analysis/pb"
)

var (
	grpcServer           *grpc.Server
	autoAnalyzeByDefault = true
	grpcAuthToken        = os.Getenv("GRPC_AUTH_TOKEN")
)

func authUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if grpcAuthToken == "" {
		return handler(ctx, req)
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	tokens := md.Get("authorization")
	if len(tokens) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization token")
	}
	if tokens[0] != "Bearer "+grpcAuthToken {
		return nil, status.Error(codes.Unauthenticated, "invalid authorization token")
	}
	return handler(ctx, req)
}

func startGrpcServer(addr string, wg *sync.WaitGroup) {
	defer wg.Done()

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer = grpc.NewServer(grpc.UnaryInterceptor(authUnaryInterceptor))
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
	events := make([]Event, 0, len(req.Events))
	pbActions := []*pb.Action{}

	for _, e := range req.Events {
		event := convertPbToEvent(e)

		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now()
		}
		if event.EventID == "" {
			event.EventID = generateEventID()
		}

		actions := processEvent(&event)

		log.Printf("Received event: %s [%s] PID=%d CMD=%s FILE=%s ADDR=%s:%d",
			event.EventType, event.EventID, event.ProcessID, event.CommandLine,
			event.FilePath, event.RemoteAddr, event.RemotePort)

		for _, a := range actions {
			// Heuristic actions are returned inline only (immediate response
			// path). Routing them through actionStore as well would make the
			// agent execute them twice: once here, once via FetchActions.
			pbActions = append(pbActions, &pb.Action{
				Id:         a.ID,
				ActionType: string(a.ActionType),
				Target:     a.Target,
				Reason:     a.Reason,
			})
		}

		events = append(events, event)
		if autoAnalyzeByDefault {
			processor.Submit(event)
		}
	}

	if esClientInstance != nil {
		evts := events
		go func() {
			if err := esClientInstance.BulkIndex(context.Background(), evts); err != nil {
				log.Printf("Failed to index gRPC events: %v", err)
			}
		}()
	}

	return &pb.IngestResponse{
		Accepted: uint32(len(req.Events)),
		Actions:  pbActions,
	}, nil
}

func (h *grpcHandler) FetchActions(ctx context.Context, req *pb.ActionRequest) (*pb.ActionResponse, error) {
	actions := actionStore.Fetch(req.HostName)
	pbActions := make([]*pb.Action, len(actions))
	for i, a := range actions {
		pbActions[i] = &pb.Action{
			Id:         a.ID,
			ActionType: string(a.ActionType),
			Target:     a.Target,
			Reason:     a.Reason,
		}
	}
	return &pb.ActionResponse{Actions: pbActions}, nil
}

func (h *grpcHandler) Analyze(ctx context.Context, req *pb.AnalysisRequest) (*pb.AnalysisResponse, error) {
	query := req.Query
	if query == "" {
		query = "ls"
	}

	if ollamaClient == nil {
		verdict := "benign"
		confidence := float32(0.5)
		if hasSuspiciousPattern(query) {
			verdict = "suspicious"
			confidence = 0.7
		}
		return &pb.AnalysisResponse{
			Verdict:    verdict,
			Confidence: confidence,
			Summary:    fmt.Sprintf("Regex-only analysis (Ollama unavailable): %s", query),
		}, nil
	}

	prompt := "Analyze this security event: " + query + "\nIs this malicious? Answer in JSON format: {\"verdict\": \"benign|suspicious|malicious\", \"confidence\": 0.0-1.0, \"summary\": \"brief explanation\"}"
	log.Printf("gRPC Analyze prompt: %s", prompt)

	response, err := ollamaClient.Generate(ctx, prompt)
	if err != nil {
		log.Printf("Ollama generation failed: %v", err)
		verdict := "benign"
		confidence := float32(0.3)
		if hasSuspiciousPattern(query) {
			verdict = "suspicious"
			confidence = 0.7
		}
		return &pb.AnalysisResponse{
			Verdict:    verdict,
			Confidence: confidence,
			Summary:    fmt.Sprintf("Ollama failed, regex fallback: %s", query),
		}, nil
	}

	verdict, confidenceFloat64, evidence, summary, _, _ := parseAnalysisResponse(response)

	return &pb.AnalysisResponse{
		Verdict:    verdict,
		Confidence: float32(confidenceFloat64),
		Summary:    summary,
		Evidence:   evidence,
	}, nil
}

func hasSuspiciousPattern(cmd string) bool {
	if cmd == "" {
		return false
	}

	for _, rule := range DefaultRules.CommandRules {
		if rule.Pattern.MatchString(cmd) {
			return true
		}
	}

	return false
}

func convertPbToEvent(e *pb.Event) Event {
	var flagsDesc string
	if e.FlagsDesc != "" {
		flagsDesc = e.FlagsDesc
	} else {
		flagsDesc = strconv.FormatInt(int64(e.Flags), 10)
	}

	return Event{
		Timestamp:   parseTimestamp(e.Timestamp),
		HostName:    e.HostName,
		EventType:   e.EventType,
		EventID:     e.EventId,
		ProcessGUID: e.ProcessGuid,
		ParentGUID:  e.ParentGuid,
		ProcessID:   e.ProcessId,
		ParentPID:   e.ParentPid,
		ImagePath:   e.ImagePath,
		CommandLine: e.CommandLine,
		FilePath:    e.FilePath,
		FileFlags:   flagsDesc,
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
