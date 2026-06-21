package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type OllamaConfig struct {
	Address    string
	Model      string
	EmbedModel string
	EmbedDim   int
	Timeout    time.Duration
}

type OllamaBackend struct {
	cfg    OllamaConfig
	client *http.Client
}

func NewOllama(cfg OllamaConfig) *OllamaBackend {
	if cfg.Model == "" {
		cfg.Model = "qwen2.5:7b"
	}
	if cfg.EmbedModel == "" {
		cfg.EmbedModel = "nomic-embed-text"
	}
	if cfg.EmbedDim == 0 {
		cfg.EmbedDim = 768
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Minute
	}

	return &OllamaBackend{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

func (o *OllamaBackend) Name() string {
	return fmt.Sprintf("ollama/%s", o.cfg.Model)
}

func (o *OllamaBackend) Analyze(req AnalysisRequest) (*AnalysisResult, error) {
	prompt := buildPrompt(req)

	resp, err := o.generate(context.Background(), prompt)
	if err != nil {
		return nil, fmt.Errorf("ollama generate: %w", err)
	}

	result, err := parseResponse(resp)
	if err != nil {
		log.Printf("Ollama response parse failed: %v, raw: %s", err, resp)
		return &AnalysisResult{
			Verdict:    "unknown",
			Confidence: 0.0,
			Summary:    "Failed to parse Ollama response",
			ModelUsed:  o.cfg.Model,
			Timestamp:  time.Now(),
		}, nil
	}

	result.ModelUsed = o.cfg.Model
	result.Timestamp = time.Now()
	return result, nil
}

func (o *OllamaBackend) GetEmbedding(ctx context.Context, text string) ([]float32, error) {
	if text == "" {
		return make([]float32, o.cfg.EmbedDim), nil
	}

	reqBody := map[string]any{
		"model":  o.cfg.EmbedModel,
		"prompt": text,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal embedding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		o.cfg.Address+"/api/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create embedding request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embedding request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("embedding failed: %s %s", resp.Status, respBody)
	}

	var embResp struct {
		Embedding []float32 `json:"embedding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&embResp); err != nil {
		return nil, fmt.Errorf("decode embedding: %w", err)
	}

	return embResp.Embedding, nil
}

func (o *OllamaBackend) BatchEmbed(ctx context.Context, texts []string) ([][]float32, error) {
	embeddings := make([][]float32, 0, len(texts))
	for _, text := range texts {
		emb, err := o.GetEmbedding(ctx, text)
		if err != nil {
			return nil, err
		}
		embeddings = append(embeddings, emb)
	}
	return embeddings, nil
}

func (o *OllamaBackend) generate(ctx context.Context, prompt string) (string, error) {
	reqBody := map[string]any{
		"model":  o.cfg.Model,
		"prompt": prompt,
		"stream": false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal generate request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		o.cfg.Address+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create generate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("generate request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("generate failed: %s %s", resp.Status, respBody)
	}

	var genResp struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		return "", fmt.Errorf("decode generate: %w", err)
	}

	return genResp.Response, nil
}

func buildPrompt(req AnalysisRequest) string {
	var buf bytes.Buffer

	buf.WriteString("You are a security analyst analyzing process execution telemetry. ")
	buf.WriteString("Your task is to identify suspicious or malicious behavior patterns.\n\n")
	buf.WriteString("IMPORTANT: Only flag behavior that is clearly malicious with high confidence. ")
	buf.WriteString("If in doubt, classify as benign.\n\n")

	buf.WriteString(fmt.Sprintf("Host: %s\n", req.HostName))
	buf.WriteString(fmt.Sprintf("Interestingness score: %.2f\n\n", req.Interestingness))

	buf.WriteString("## Events in this batch\n")
	buf.WriteString("| Timestamp | Type | PID | Image | Command Line |\n")
	buf.WriteString("|-----------|------|-----|-------|--------------|\n")
	for _, e := range req.Events {
		buf.WriteString(fmt.Sprintf("| N/A | %s | %d | %s | %s |\n",
			e.GetEventType(), e.GetProcessID(),
			truncate(e.GetImagePath(), 40),
			truncate(e.GetCommandLine(), 60)))
	}

	if len(req.ProcessChains) > 0 {
		buf.WriteString("\n## Process Ancestry\n")
		for parentGUID, chain := range req.ProcessChains {
			buf.WriteString(fmt.Sprintf("**Parent: %s**\n", parentGUID))
			for _, e := range chain {
				buf.WriteString(fmt.Sprintf("- %s %s %s\n",
					e.GetEventType(), e.GetImagePath(), truncate(e.GetCommandLine(), 50)))
			}
		}
	}

	if len(req.SimilarIncidents) > 0 {
		buf.WriteString("\n## Similar Labeled Incidents\n")
		buf.WriteString("These past incidents match the current event pattern:\n")
		for _, inc := range req.SimilarIncidents {
			verified := ""
			if inc.Verified {
				verified = " (verified)"
			}
			buf.WriteString(fmt.Sprintf("- Incident %s: verdict=%s%s\n  %s\n",
				inc.ID, inc.Verdict, verified, inc.Summary))
		}
	}

	buf.WriteString("\n## Analysis Guidelines\n")
	buf.WriteString("Look for:\n")
	buf.WriteString("- Cryptominer execution (xmrig, minerd, ccminer, etc.)\n")
	buf.WriteString("- Reverse shell patterns (bash -i, nc -e, /dev/tcp)\n")
	buf.WriteString("- Privilege escalation\n")
	buf.WriteString("- Process chains: downloaded content → execute → connect\n")
	buf.WriteString("- High volumes of connections to mining pools on ports 3333, 4444, etc.\n")
	buf.WriteString("- Execution from /tmp, /dev/shm\n\n")

	buf.WriteString(`## Output Format (JSON only)
{
  "verdict": "benign|suspicious|malicious",
  "confidence": 0.0-1.0,
  "evidence": ["list of indicators"],
  "summary": "concise explanation (1-2 sentences)"
}`)

	return buf.String()
}

func parseResponse(resp string) (*AnalysisResult, error) {
	jsonStr := extractJSON(resp)

	var result struct {
		Verdict    string   `json:"verdict"`
		Confidence float64  `json:"confidence"`
		Evidence   []string `json:"evidence"`
		Summary    string   `json:"summary"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("parse response JSON: %w", err)
	}

	return &AnalysisResult{
		Verdict:    result.Verdict,
		Confidence: result.Confidence,
		Evidence:   result.Evidence,
		Summary:    result.Summary,
	}, nil
}

func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	start := strings.Index(s, "{")
	if start == -1 {
		return s
	}

	braceCount := 0
	end := -1
	for i := start; i < len(s); i++ {
		if s[i] == '{' {
			braceCount++
		} else if s[i] == '}' {
			braceCount--
			if braceCount == 0 {
				end = i + 1
				break
			}
		}
	}

	if end > start {
		return s[start:end]
	}
	return s
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-3]) + "..."
}
