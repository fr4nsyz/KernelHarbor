package llm

import (
	"testing"
)

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain json", `{"verdict": "malicious", "confidence": 0.9}`, `{"verdict": "malicious", "confidence": 0.9}`},
		{"json with markdown code block", "```json\n{\"verdict\": \"malicious\", \"confidence\": 0.9}\n```", `{"verdict": "malicious", "confidence": 0.9}`},
		{"json with text before", "The analysis shows:\n```json\n{\"verdict\": \"benign\", \"confidence\": 1.0}\n```", `{"verdict": "benign", "confidence": 1.0}`},
		{"json with text before and after", "Analysis complete. ```json\n{\"verdict\": \"suspicious\", \"confidence\": 0.8}\n``` is the result.", `{"verdict": "suspicious", "confidence": 0.8}`},
		{"no json found", "This is just plain text", "This is just plain text"},
		{"empty braces", "{}", "{}"},
		{"json with newlines", "```json\n{\n  \"verdict\": \"benign\",\n  \"confidence\": 1.0\n}\n```", "{\n  \"verdict\": \"benign\",\n  \"confidence\": 1.0\n}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSON(tt.input)
			if got != tt.want {
				t.Errorf("extractJSON() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantVerdict    string
		wantConfidence float64
		wantSummary    string
		wantErr        bool
	}{
		{
			name:           "valid json verdict malicious",
			input:          `{"verdict": "malicious", "confidence": 0.9, "summary": "test"}`,
			wantVerdict:    "malicious",
			wantConfidence: 0.9,
			wantSummary:    "test",
		},
		{
			name:           "valid json verdict benign",
			input:          `{"verdict": "benign", "confidence": 1.0, "summary": "normal command"}`,
			wantVerdict:    "benign",
			wantConfidence: 1.0,
			wantSummary:    "normal command",
		},
		{
			name:           "json in markdown code block",
			input:          "```json\n{\"verdict\": \"suspicious\", \"confidence\": 0.8, \"summary\": \"lolbin usage\"}\n```",
			wantVerdict:    "suspicious",
			wantConfidence: 0.8,
			wantSummary:    "lolbin usage",
		},
		{
			name:           "json with leading text",
			input:          "Analysis result: ```json\n{\"verdict\": \"malicious\", \"confidence\": 0.95, \"summary\": \"reverse shell\"}\n```",
			wantVerdict:    "malicious",
			wantConfidence: 0.95,
			wantSummary:    "reverse shell",
		},
		{
			name:    "invalid json returns error",
			input:   "not json at all",
			wantErr: true,
		},
		{
			name:           "missing verdict field",
			input:          `{"confidence": 0.9, "summary": "test"}`,
			wantConfidence: 0.9,
			wantSummary:    "test",
		},
		{
			name:  "empty json",
			input: "{}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseResponse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if result.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", result.Verdict, tt.wantVerdict)
			}

			if result.Confidence != tt.wantConfidence {
				t.Errorf("confidence = %v, want %v", result.Confidence, tt.wantConfidence)
			}

			if result.Summary != tt.wantSummary {
				t.Errorf("summary = %q, want %q", result.Summary, tt.wantSummary)
			}
		})
	}
}
