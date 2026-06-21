package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type AnthropicConfig struct {
	APIKey  string
	Model   string
	Timeout time.Duration
}

type AnthropicBackend struct {
	cfg    AnthropicConfig
	client *http.Client
}

func NewAnthropic(cfg AnthropicConfig) *AnthropicBackend {
	if cfg.Model == "" {
		cfg.Model = "claude-3-haiku-20240307"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Minute
	}
	return &AnthropicBackend{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (a *AnthropicBackend) Name() string {
	return fmt.Sprintf("anthropic/%s", a.cfg.Model)
}

func (a *AnthropicBackend) Analyze(req AnalysisRequest) (*AnalysisResult, error) {
	systemPrompt := `You are a security analyst evaluating system call events.
Classify the event batch as benign, suspicious, or malicious.
Be conservative — only flag as malicious with strong evidence.
Output valid JSON only. No markdown, no code fences.`

	var eventsText bytes.Buffer
	eventsText.WriteString(fmt.Sprintf("Host: %s (interestingness: %.2f)\n\nEvents:\n", req.HostName, req.Interestingness))
	for _, e := range req.Events {
		eventsText.WriteString(fmt.Sprintf("- %s pid=%d image=%s cmd=%s\n",
			e.GetEventType(), e.GetProcessID(), e.GetImagePath(), e.GetCommandLine()))
	}
	if len(req.SimilarIncidents) > 0 {
		eventsText.WriteString("\nSimilar past incidents:\n")
		for _, inc := range req.SimilarIncidents {
			eventsText.WriteString(fmt.Sprintf("  %s: %s (verified=%v)\n", inc.ID, inc.Verdict, inc.Verified))
		}
	}
	eventsText.WriteString("\nJSON output: {\"verdict\": \"benign|suspicious|malicious\", \"confidence\": 0.0-1.0, \"evidence\": [], \"summary\": \"\"}")

	reqBody := map[string]any{
		"model":       a.cfg.Model,
		"system":      systemPrompt,
		"messages":    []map[string]string{{"role": "user", "content": eventsText.String()}},
		"temperature": 0.1,
		"max_tokens":  500,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.cfg.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic api: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("anthropic api error %d: %s", resp.StatusCode, string(respBody))
	}

	var msgResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &msgResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(msgResp.Content) == 0 {
		return nil, fmt.Errorf("no content in response")
	}

	result, err := parseResponse(msgResp.Content[0].Text)
	if err != nil {
		return nil, fmt.Errorf("parse analysis: %w", err)
	}

	result.ModelUsed = a.cfg.Model
	result.Timestamp = time.Now()
	return result, nil
}
