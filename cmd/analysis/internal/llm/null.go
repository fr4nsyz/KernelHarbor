package llm

import (
	"log"
	"time"
)

type NullBackend struct{}

func NewNull() *NullBackend {
	return &NullBackend{}
}

func (n *NullBackend) Analyze(req AnalysisRequest) (*AnalysisResult, error) {
	log.Printf("LLM backend disabled, skipping analysis for %s (interestingness=%.2f)",
		req.HostName, req.Interestingness)
	return &AnalysisResult{
		Verdict:    "benign",
		Confidence: 0.0,
		Summary:    "LLM backend disabled",
		ModelUsed:  "none",
		Timestamp:  time.Now(),
	}, nil
}

func (n *NullBackend) Name() string {
	return "none"
}
