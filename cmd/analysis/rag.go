package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type OllamaConfig struct {
	Address    string
	Model      string
	EmbedModel string
	EmbedDim   int
}

type EmbeddingRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type EmbeddingResponse struct {
	Embedding []float32 `json:"embedding"`
}

type GenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type GenerateResponse struct {
	Response string `json:"response"`
}

type OllamaClient struct {
	cfg    OllamaConfig
	client *http.Client
}

func NewOllamaClient(cfg OllamaConfig) *OllamaClient {
	return &OllamaClient{
		cfg: cfg,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (o *OllamaClient) GetEmbedding(ctx context.Context, text string) ([]float32, error) {
	if text == "" {
		return make([]float32, o.cfg.EmbedDim), nil
	}

	embedModel := o.cfg.EmbedModel
	if embedModel == "" {
		embedModel = o.cfg.Model
	}

	reqBody := EmbeddingRequest{
		Model:  embedModel,
		Prompt: text,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal embedding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", o.cfg.Address+"/api/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create embedding request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get embedding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("embedding request failed: %s %s", resp.Status, respBody)
	}

	var embResp EmbeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&embResp); err != nil {
		return nil, fmt.Errorf("failed to decode embedding response: %w", err)
	}

	return embResp.Embedding, nil
}

func (o *OllamaClient) Generate(ctx context.Context, prompt string) (string, error) {
	reqBody := GenerateRequest{
		Model:  o.cfg.Model,
		Prompt: prompt,
		Stream: false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal generate request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", o.cfg.Address+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create generate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to generate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("generate request failed: %s %s", resp.Status, respBody)
	}

	var genResp GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		return "", fmt.Errorf("failed to decode generate response: %w", err)
	}

	return genResp.Response, nil
}

func (o *OllamaClient) BatchEmbed(ctx context.Context, texts []string) ([][]float32, error) {
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

var ollamaClient *OllamaClient

func buildAnalysisPrompt(events []Event, similarEvents []Event) string {
	var prompt bytes.Buffer

	prompt.WriteString("You are a security analyst analyzing process execution telemetry. ")
	prompt.WriteString("Examine the following batch of events for suspicious or malicious behavior.\n\n")

	prompt.WriteString("## Current Event Batch\n")
	prompt.WriteString("| Timestamp | Type | PID | Image | Command Line | User |\n")
	prompt.WriteString("|-----------|------|-----|-------|--------------|------|\n")
	for _, e := range events {
		prompt.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s | %s |\n",
			e.Timestamp.Format(time.RFC3339),
			e.EventType,
			e.ProcessID,
			truncate(e.ImagePath, 40),
			truncate(e.CommandLine, 50),
			e.User,
		))
	}

	if len(similarEvents) > 0 {
		prompt.WriteString("\n## Similar Past Events (for reference)\n")
		prompt.WriteString("| Timestamp | Type | Image | Command Line |\n")
		prompt.WriteString("|-----------|------|-------|--------------|\n")
		for _, e := range similarEvents {
			prompt.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				e.Timestamp.Format(time.RFC3339),
				e.EventType,
				truncate(e.ImagePath, 30),
				truncate(e.CommandLine, 40),
			))
		}
	}

	prompt.WriteString("\n## Analysis Guidelines\n")
	prompt.WriteString("Look for:\n")
	prompt.WriteString("- Unusual parent processes (e.g., office app spawning cmd.exe)\n")
	prompt.WriteString("- LOLBins (Living Off the Land binaries) in suspicious contexts\n")
	prompt.WriteString("- Unusual command line arguments (encoded commands, suspicious flags)\n")
	prompt.WriteString("- Process execution from temp directories or unusual locations\n")
	prompt.WriteString("- Network connections from spawned processes\n")
	prompt.WriteString("- Privilege escalation patterns\n\n")

	prompt.WriteString("## Output Format\n")
	prompt.WriteString("Provide your analysis in JSON format:\n")
	prompt.WriteString("```json\n")
	prompt.WriteString("{\n")
	prompt.WriteString("  \"verdict\": \"benign|suspicious|malicious\",\n")
	prompt.WriteString("  \"confidence\": 0.0-1.0,\n")
	prompt.WriteString("  \"evidence\": [\"list of suspicious indicators\"],\n")
	prompt.WriteString("  \"summary\": \"brief explanation\"\n")
	prompt.WriteString("}\n")
	prompt.WriteString("```\n")

	return prompt.String()
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-3]) + "..."
}

func parseAnalysisResponse(response string) (string, float64, []string, string, error) {
	jsonStr := extractJSON(response)

	var result struct {
		Verdict    string   `json:"verdict"`
		Confidence float64  `json:"confidence"`
		Evidence   []string `json:"evidence"`
		Summary    string   `json:"summary"`
	}

	decoder := json.NewDecoder(bytes.NewReader([]byte(jsonStr)))
	if err := decoder.Decode(&result); err != nil {
		return "unknown", 0.0, nil, response, fmt.Errorf("failed to parse analysis: %w", err)
	}

	return result.Verdict, result.Confidence, result.Evidence, result.Summary, nil
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
