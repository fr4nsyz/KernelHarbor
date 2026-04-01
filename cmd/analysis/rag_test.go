package main

import (
	"testing"
)

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "plain json",
			input:   `{"verdict": "malicious", "confidence": 0.9}`,
			want:    `{"verdict": "malicious", "confidence": 0.9}`,
			wantErr: false,
		},
		{
			name:    "json with markdown code block",
			input:   "```json\n{\"verdict\": \"malicious\", \"confidence\": 0.9}\n```",
			want:    `{"verdict": "malicious", "confidence": 0.9}`,
			wantErr: false,
		},
		{
			name:    "json with text before",
			input:   "The analysis shows:\n```json\n{\"verdict\": \"benign\", \"confidence\": 1.0}\n```",
			want:    `{"verdict": "benign", "confidence": 1.0}`,
			wantErr: false,
		},
		{
			name:    "json with text before and after",
			input:   "Analysis complete. ```json\n{\"verdict\": \"suspicious\", \"confidence\": 0.8}\n``` is the result.",
			want:    `{"verdict": "suspicious", "confidence": 0.8}`,
			wantErr: false,
		},
		{
			name:    "no json found",
			input:   "This is just plain text",
			want:    "This is just plain text",
			wantErr: false,
		},
		{
			name:    "nested json",
			input:   "```json\n{\"verdict\": \"malicious\", \"summary\": \"test with nested \\\"quotes\\\"\"}\n```",
			want:    `{"verdict": "malicious", "summary": "test with nested \"quotes\""}`,
			wantErr: false,
		},
		{
			name:    "empty braces",
			input:   "{}",
			want:    "{}",
			wantErr: false,
		},
		{
			name:    "json with newlines",
			input:   "```json\n{\n  \"verdict\": \"benign\",\n  \"confidence\": 1.0\n}\n```",
			want:    "{\n  \"verdict\": \"benign\",\n  \"confidence\": 1.0\n}",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSON(tt.input)
			if got != tt.want {
				t.Errorf("extractJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseAnalysisResponse(t *testing.T) {
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
			wantErr:        false,
		},
		{
			name:           "valid json verdict benign",
			input:          `{"verdict": "benign", "confidence": 1.0, "summary": "normal command"}`,
			wantVerdict:    "benign",
			wantConfidence: 1.0,
			wantSummary:    "normal command",
			wantErr:        false,
		},
		{
			name:           "json in markdown code block",
			input:          "```json\n{\"verdict\": \"suspicious\", \"confidence\": 0.8, \"summary\": \"lolbin usage\"}\n```",
			wantVerdict:    "suspicious",
			wantConfidence: 0.8,
			wantSummary:    "lolbin usage",
			wantErr:        false,
		},
		{
			name:           "json with leading text",
			input:          "Analysis result: ```json\n{\"verdict\": \"malicious\", \"confidence\": 0.95, \"summary\": \"reverse shell\"}\n```",
			wantVerdict:    "malicious",
			wantConfidence: 0.95,
			wantSummary:    "reverse shell",
			wantErr:        false,
		},
		{
			name:           "invalid json returns error",
			input:          "not json at all",
			wantVerdict:    "unknown",
			wantConfidence: 0.0,
			wantErr:        true,
		},
		{
			name:           "missing verdict field",
			input:          `{"confidence": 0.9, "summary": "test"}`,
			wantVerdict:    "",
			wantConfidence: 0.9,
			wantSummary:    "test",
			wantErr:        false,
		},
		{
			name:           "empty json",
			input:          "{}",
			wantVerdict:    "",
			wantConfidence: 0.0,
			wantSummary:    "",
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVerdict, gotConfidence, _, gotSummary, err := parseAnalysisResponse(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseAnalysisResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if gotVerdict != tt.wantVerdict {
				t.Errorf("verdict = %v, want %v", gotVerdict, tt.wantVerdict)
			}

			if gotConfidence != tt.wantConfidence {
				t.Errorf("confidence = %v, want %v", gotConfidence, tt.wantConfidence)
			}

			if !tt.wantErr && gotSummary != tt.wantSummary {
				t.Errorf("summary = %v, want %v", gotSummary, tt.wantSummary)
			}
		})
	}
}
