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

const defaultLayaTimeout = 30 * time.Second

type LayaConfig struct {
	Address string
	APIKey  string
	Model   string
	Timeout time.Duration
}

type LayaClient struct {
	address string
	apiKey  string
	model   string
	http    *http.Client
}

type LayaChoiceQuestion struct {
	Type         string            `json:"type"`
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria"`
}

type LayaRequest struct {
	State     any                           `json:"state"`
	Questions map[string]LayaChoiceQuestion `json:"questions"`
	Model     string                        `json:"model,omitempty"`
}

type LayaAnswer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice"`
	Confidence    float64            `json:"confidence"`
	Probabilities map[string]float64 `json:"probabilities"`
}

type LayaResponse struct {
	ID      string                `json:"id"`
	Model   string                `json:"model"`
	Answers map[string]LayaAnswer `json:"answers"`
}

func NewLayaClient(cfg LayaConfig) *LayaClient {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultLayaTimeout
	}

	return &LayaClient{
		address: strings.TrimRight(cfg.Address, "/"),
		apiKey:  cfg.APIKey,
		model:   cfg.Model,
		http:    &http.Client{Timeout: timeout},
	}
}

func (c *LayaClient) post(ctx context.Context, path string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode laya request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.address+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to build laya request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("laya request failed: %w", err)
	}
	defer res.Body.Close()

	payloadBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read laya response: %w", err)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("laya returned %d: %s", res.StatusCode, strings.TrimSpace(string(payloadBytes)))
	}

	if err := json.Unmarshal(payloadBytes, out); err != nil {
		return fmt.Errorf("failed to decode laya response: %w", err)
	}

	return nil
}

// Choose asks a single choice question about the given state and returns the answer.
func (c *LayaClient) Choose(
	ctx context.Context,
	state any,
	questionID string,
	instructions string,
	criteria map[string]string,
) (LayaAnswer, error) {
	if len(criteria) == 0 {
		return LayaAnswer{}, fmt.Errorf("question %s has no criteria", questionID)
	}
	if len(criteria) > MaxChoiceOptions {
		return LayaAnswer{}, fmt.Errorf("question %s has %d options, limit is %d", questionID, len(criteria), MaxChoiceOptions)
	}

	req := LayaRequest{
		State: state,
		Questions: map[string]LayaChoiceQuestion{
			questionID: {
				Type:         "choice",
				Instructions: instructions,
				Criteria:     criteria,
			},
		},
		Model: c.model,
	}

	var res LayaResponse
	if err := c.post(ctx, "/v1/systemone", req, &res); err != nil {
		return LayaAnswer{}, err
	}

	answer, ok := res.Answers[questionID]
	if !ok {
		return LayaAnswer{}, fmt.Errorf("laya response missing answer for %s", questionID)
	}

	if _, ok := criteria[answer.Choice]; !ok {
		return LayaAnswer{}, fmt.Errorf("laya returned unknown choice %q for %s", answer.Choice, questionID)
	}

	return answer, nil
}

func (c *LayaClient) Healthy(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.address+"/health", nil)
	if err != nil {
		return false
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)

	return res.StatusCode >= 200 && res.StatusCode < 300
}
