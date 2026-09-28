package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func layaTestServer(t *testing.T, handler func(w http.ResponseWriter, body []byte)) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
			return
		}
		handler(w, body)
	}))
	t.Cleanup(server.Close)

	return server
}

func writeLayaAnswer(w http.ResponseWriter, answer LayaAnswer) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(LayaResponse{
		ID:    "test-decision",
		Model: "english",
		Answers: map[string]LayaAnswer{
			"tactic": answer,
		},
	})
}

func TestLayaChooseSendsSystemOneRequest(t *testing.T) {
	var got LayaRequest
	var gotPath string
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("failed to decode request: %v", err)
			return
		}
		writeLayaAnswer(w, LayaAnswer{Type: "choice", Choice: "execution", Confidence: 0.82})
	}))
	defer srv.Close()

	client := NewLayaClient(LayaConfig{Address: srv.URL, APIKey: "lsk_live_test", Model: "english"})

	answer, err := client.Choose(context.Background(),
		map[string]any{"event_type": "execve"},
		"tactic", "which tactic?",
		map[string]string{"execution": "running code", "benign": "routine"},
	)
	if err != nil {
		t.Fatalf("Choose returned error: %v", err)
	}

	if gotPath != "/v1/systemone" {
		t.Errorf("request path = %q, want /v1/systemone", gotPath)
	}
	if gotAuth != "Bearer lsk_live_test" {
		t.Errorf("Authorization = %q, want Bearer lsk_live_test", gotAuth)
	}

	if got.Model != "english" {
		t.Errorf("model = %q, want english", got.Model)
	}
	question, ok := got.Questions["tactic"]
	if !ok {
		t.Fatalf("request has no tactic question: %+v", got.Questions)
	}
	if question.Type != "choice" {
		t.Errorf("question type = %q, want choice", question.Type)
	}
	if question.Instructions != "which tactic?" {
		t.Errorf("instructions = %q", question.Instructions)
	}
	if len(question.Criteria) != 2 || question.Criteria["execution"] != "running code" {
		t.Errorf("criteria = %v", question.Criteria)
	}
	if state, ok := got.State.(map[string]any); !ok || state["event_type"] != "execve" {
		t.Errorf("state = %v", got.State)
	}

	if answer.Choice != "execution" {
		t.Errorf("choice = %q, want execution", answer.Choice)
	}
	if answer.Confidence != 0.82 {
		t.Errorf("confidence = %v, want 0.82", answer.Confidence)
	}
}

func TestLayaChooseWithoutAPIKeyOmitsAuth(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		writeLayaAnswer(w, LayaAnswer{Type: "choice", Choice: "execution", Confidence: 0.9})
	}))
	defer srv.Close()

	client := NewLayaClient(LayaConfig{Address: srv.URL})
	if _, err := client.Choose(context.Background(), "state", "tactic", "q", map[string]string{"execution": "x"}); err != nil {
		t.Fatalf("Choose returned error: %v", err)
	}

	if auth != "" {
		t.Errorf("Authorization = %q, want empty when no API key configured", auth)
	}
}

func TestLayaChooseRejectsOversizedChoiceSet(t *testing.T) {
	criteria := make(map[string]string, MaxChoiceOptions+1)
	for i := 0; i <= MaxChoiceOptions; i++ {
		criteria[string(rune('a'+i))] = "desc"
	}

	client := NewLayaClient(LayaConfig{Address: "http://127.0.0.1:1"})

	_, err := client.Choose(context.Background(), "state", "tactic", "q", criteria)
	if err == nil {
		t.Fatal("expected an error for an oversized choice set")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error = %v, want a limit complaint", err)
	}
}

func TestLayaChooseRejectsEmptyCriteria(t *testing.T) {
	client := NewLayaClient(LayaConfig{Address: "http://127.0.0.1:1"})

	if _, err := client.Choose(context.Background(), "state", "tactic", "q", nil); err == nil {
		t.Fatal("expected an error when no criteria are provided")
	}
}

func TestLayaChooseRejectsChoiceOutsideCriteria(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeLayaAnswer(w, LayaAnswer{Type: "choice", Choice: "hallucinated", Confidence: 0.99})
	}))
	defer srv.Close()

	client := NewLayaClient(LayaConfig{Address: srv.URL})

	_, err := client.Choose(context.Background(), "state", "tactic", "q", map[string]string{"execution": "x"})
	if err == nil {
		t.Fatal("expected an error for a choice outside the criteria")
	}
	if !strings.Contains(err.Error(), "hallucinated") {
		t.Errorf("error = %v, want it to name the unknown choice", err)
	}
}

func TestLayaChooseHandlesMissingAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"english","answers":{"other":{"type":"choice","choice":"execution","confidence":0.9}}}`))
	}))
	defer srv.Close()

	client := NewLayaClient(LayaConfig{Address: srv.URL})

	if _, err := client.Choose(context.Background(), "state", "tactic", "q", map[string]string{"execution": "x"}); err == nil {
		t.Fatal("expected an error when the requested answer is missing")
	}
}

func TestLayaChooseSurfacesHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte("question tactic: criteria too large"))
	}))
	defer srv.Close()

	client := NewLayaClient(LayaConfig{Address: srv.URL})

	_, err := client.Choose(context.Background(), "state", "tactic", "q", map[string]string{"execution": "x"})
	if err == nil {
		t.Fatal("expected an error for HTTP 422")
	}
	if !strings.Contains(err.Error(), "422") || !strings.Contains(err.Error(), "criteria too large") {
		t.Errorf("error = %v, want status and server message", err)
	}
}

func TestLayaChooseRespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		writeLayaAnswer(w, LayaAnswer{Type: "choice", Choice: "execution", Confidence: 0.9})
	}))
	defer srv.Close()

	client := NewLayaClient(LayaConfig{Address: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if _, err := client.Choose(ctx, "state", "tactic", "q", map[string]string{"execution": "x"}); err == nil {
		t.Fatal("expected an error when the context expires")
	}
}

func TestLayaHealthy(t *testing.T) {
	srv := layaTestServer(t, func(w http.ResponseWriter, body []byte) {})
	client := NewLayaClient(LayaConfig{Address: srv.URL})
	if !client.Healthy(context.Background()) {
		t.Error("expected Healthy to report the reachable server as healthy")
	}

	down := NewLayaClient(LayaConfig{Address: "http://127.0.0.1:1"})
	if down.Healthy(context.Background()) {
		t.Error("expected Healthy to report an unreachable server as unhealthy")
	}
}

func TestLayaClientTrimsTrailingSlashInAddress(t *testing.T) {
	client := NewLayaClient(LayaConfig{Address: "http://localhost:8000/"})
	if client.address != "http://localhost:8000" {
		t.Errorf("address = %q, want the trailing slash removed", client.address)
	}
}
