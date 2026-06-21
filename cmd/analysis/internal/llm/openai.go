package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type OpenAIConfig struct {
	APIKey  string
	Model   string
	Timeout time.Duration
}

type OpenAIBackend struct {
	cfg    OpenAIConfig
	client *http.Client
}

func NewOpenAI(cfg OpenAIConfig) *OpenAIBackend {
	if cfg.Model == "" {
		cfg.Model = "gpt-4o-mini"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Minute
	}
	return &OpenAIBackend{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (o *OpenAIBackend) Name() string {
	return fmt.Sprintf("openai/%s", o.cfg.Model)
}

func (o *OpenAIBackend) Analyze(req AnalysisRequest) (*AnalysisResult, error) {
	systemPrompt := `You are a security analyst evaluating system call events. 
Classify the event batch as benign, suspicious, or malicious.
Be conservative — only flag as malicious with strong evidence.
Output valid JSON only: {"verdict": "benign|suspicious|malicious", "confidence": 0.0-1.0, "evidence": [...], "summary": "..."}`

	var eventsText bytes.Buffer
	eventsText.WriteString(fmt.Sprintf("Host: %s (interestingness: %.2f)\n", req.HostName, req.Interestingness))
	for _, e := range req.Events {
		eventsText.WriteString(fmt.Sprintf("- %s pid=%d image=%s cmd=%s\n",
			e.GetEventType(), e.GetProcessID(), e.GetImagePath(), e.GetCommandLine()))
	}

	userMsg := eventsText.String()
	if len(req.SimilarIncidents) > 0 {
		userMsg += "\nSimilar past incidents (labeled):\n"
		for _, inc := range req.SimilarIncidents {
			userMsg += fmt.Sprintf("  %s: %s (verified=%v)\n", inc.ID, inc.Verdict, inc.Verified)
		}
	}

	reqBody := map[string]any{
		"model": o.cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userMsg},
		},
		"temperature": 0.1,
		"max_tokens":  500,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.cfg.APIKey)

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai api: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("openai api error %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	result, err := parseResponse(chatResp.Choices[0].Message.Content)
	if err != nil {
		return nil, fmt.Errorf("parse analysis: %w", err)
	}

	result.ModelUsed = o.cfg.Model
	result.Timestamp = time.Now()
	return result, nil
}
