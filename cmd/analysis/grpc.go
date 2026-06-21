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

	"KernelHarbor/cmd/analysis/internal/llm"
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

		query := event.CommandLine
		if query == "" {
			query = event.FilePath
		}
		if query == "" {
			query = event.RemoteAddr
		}

		verdict := "benign"
		confidence := float32(0.0)
		if query != "" {
			if hasSuspiciousPattern(query) {
				verdict = "suspicious"
				confidence = 0.7
				action := Action{
					ID:         generateEventID(),
					Timestamp:  time.Now(),
					HostName:   event.HostName,
					ActionType: ActionKillPID,
					Target:     strconv.Itoa(int(event.ProcessID)),
					Reason:     fmt.Sprintf("Heuristic match: %s", query),
				}
				actionStore.Add(event.HostName, action)
				addHeuristicAlert(event)
				pbActions = append(pbActions, &pb.Action{
					Id:         action.ID,
					ActionType: string(action.ActionType),
					Target:     action.Target,
					Reason:     action.Reason,
				})
			} else {
				confidence = 0.3
			}
		}

		log.Printf("Received event: %s [%s] PID=%d CMD=%s | VERDICT=%s CONFIDENCE=%.2f",
			event.EventType, event.EventID, event.ProcessID, event.CommandLine, verdict, confidence)

		events = append(events, event)
		processor.Submit(event)
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

	if llmBackend == nil || llmBackend.Name() == "none" {
		verdict := "benign"
		confidence := float32(0.5)
		if hasSuspiciousPattern(query) {
			verdict = "suspicious"
			confidence = 0.7
		}
		return &pb.AnalysisResponse{
			Verdict:    verdict,
			Confidence: confidence,
			Summary:    fmt.Sprintf("Regex-only analysis (LLM unavailable): %s", query),
		}, nil
	}

	evt := Event{
		HostName:    req.HostName,
		EventType:   "analyze",
		CommandLine: query,
	}

	analysisReq := llm.AnalysisRequest{
		Events:   []llm.EventLike{grpcEventLike{evt}},
		HostName: req.HostName,
	}

	result, err := llmBackend.Analyze(analysisReq)
	if err != nil {
		log.Printf("LLM analysis failed: %v", err)
		verdict := "benign"
		confidence := float32(0.3)
		if hasSuspiciousPattern(query) {
			verdict = "suspicious"
			confidence = 0.7
		}
		return &pb.AnalysisResponse{
			Verdict:    verdict,
			Confidence: confidence,
			Summary:    fmt.Sprintf("LLM failed, regex fallback: %s", query),
		}, nil
	}

	return &pb.AnalysisResponse{
		Verdict:    result.Verdict,
		Confidence: float32(result.Confidence),
		Summary:    result.Summary,
		Evidence:   result.Evidence,
	}, nil
}

type grpcEventLike struct {
	event Event
}

func (e grpcEventLike) GetEventType() string   { return e.event.EventType }
func (e grpcEventLike) GetCommandLine() string { return e.event.CommandLine }
func (e grpcEventLike) GetImagePath() string   { return e.event.ImagePath }
func (e grpcEventLike) GetRemoteAddr() string  { return e.event.RemoteAddr }
func (e grpcEventLike) GetRemotePort() uint16  { return e.event.RemotePort }
func (e grpcEventLike) GetProcessID() uint32   { return e.event.ProcessID }
func (e grpcEventLike) GetParentGUID() string  { return e.event.ParentGUID }
func (e grpcEventLike) GetHostName() string    { return e.event.HostName }
func (e grpcEventLike) GetFilePath() string    { return e.event.FilePath }

var suspiciousPatterns = []string{
	`curl\s+[^\s]+\s*\|`,
	`curl\s+[^\s]+\s*>\s*/`,
	`curl\s+-[dTk]`,
	`curl\s+-[A-Z]-[dTk]`,
	`curl\s+-[sS].*http://[^\s]+`,
	`curl\s+-X\s+(DELETE|PUT|PATCH)`,
	`curl\s+--post-data`,
	`curl\s+--no-check-certificate`,
	`curl\s+--connect-timeout\s+\d+\s+http://`,
	`wget\s+-[OQA]`,
	`wget\s+[^\s]+\s+-[OQA]`,
	`wget\s+[^\s]+\s*\|`,
	`wget\s+[^\s]+\s*>\s*/`,
	`wget\s+--post-data`,
	`wget\s+--no-check-certificate`,
	`(ba)?sh\s+-c\s+`,
	`/bin/(ba)?sh\s+-c`,
	`bash\s+-i`,
	`sh\s+-i`,
	`nc\s+-[lveuzwp]`,
	`nc\s+-[^\s]*\s+.*-[eEpP]`,
	`nc\s+\S+\s+\d+\s+-[eEpP]`,
	`nc\s+[0-9]`,
	`ncat\s+`,
	`netcat\s+`,
	`socat\s+`,
	`base64\s+-d`,
	`powershell`,
	`python.*socket`,
	`python.*subprocess`,
	`python.*pty`,
	`python.*os\.(listdir|system|popen|exec|remove|unlink|rmdir|rename)`,
	`perl\s+-e\s+`,
	`ruby\s+-e\s+`,
	`php\s+-r\s+`,
	`/dev/tcp`,
	`/dev/udp`,
}

var dangerousExtensions = []string{`\b\S+\.sh\b`, `\.bash$`, `\.ps1$`}

var compiledSuspicious []*regexp.Regexp
var compiledExtensions []*regexp.Regexp
var compiledBenignPatterns []*regexp.Regexp

func init() {
	for _, p := range suspiciousPatterns {
		compiledSuspicious = append(compiledSuspicious, regexp.MustCompile(p))
	}
	for _, p := range dangerousExtensions {
		compiledExtensions = append(compiledExtensions, regexp.MustCompile(p))
	}
	benignShPatterns := []string{
		`chmod\s+`, `ls\s+`, `cat\s+`, `grep\s+`,
		`head\s+`, `tail\s+`, `diff\s+`, `vim\s+`,
		`nano\s+`, `less\s+`, `more\s+`, `wc\s+`,
		`file\s+`, `stat\s+`, `test\s+`,
	}
	for _, p := range benignShPatterns {
		compiledBenignPatterns = append(compiledBenignPatterns, regexp.MustCompile(p))
	}
}

func hasSuspiciousPattern(cmd string) bool {
	if cmd == "" {
		return false
	}

	for _, re := range compiledSuspicious {
		if re.MatchString(cmd) {
			return true
		}
	}

	for i, re := range compiledExtensions {
		if re.MatchString(cmd) {
			if dangerousExtensions[i] == `\b\S+\.sh\b` && isBenignShRef(cmd) {
				continue
			}
			return true
		}
	}

	return false
}

func isBenignShRef(cmd string) bool {
	for _, re := range compiledBenignPatterns {
		if re.MatchString(cmd) {
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
