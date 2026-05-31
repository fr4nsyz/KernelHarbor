package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

type BenchReport struct {
	Timestamp            time.Time
	EventThroughput      string
	AvgAnalysisLatency   string
	P50Latency           string
	P95Latency           string
	P99Latency           string
	AgentCPUOverhead     string
	MemoryUsageMB        float64
	EventDropRate        float64
	TruePositives        int
	FalsePositives       int
	TrueNegatives        int
	FalseNegatives       int
	Accuracy             float64
	Precision            float64
	Recall               float64
	F1Score              float64
	FPRate               float64
	ESIndexingThroughput string
	OllamaEmbedLatency   string
	OllamaGenLatency     string
}

func (r *BenchReport) ToMarkdown() string {
	var sb strings.Builder

	sb.WriteString("# KernelHarbor Benchmark Report\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", r.Timestamp.Format(time.RFC3339)))

	sb.WriteString("## Performance Metrics\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Event throughput | %s |\n", r.EventThroughput))
	sb.WriteString(fmt.Sprintf("| Avg analysis latency | %s |\n", r.AvgAnalysisLatency))
	sb.WriteString(fmt.Sprintf("| p50 analysis latency | %s |\n", r.P50Latency))
	sb.WriteString(fmt.Sprintf("| p95 analysis latency | %s |\n", r.P95Latency))
	sb.WriteString(fmt.Sprintf("| p99 analysis latency | %s |\n", r.P99Latency))
	sb.WriteString(fmt.Sprintf("| Agent CPU overhead | %s |\n", r.AgentCPUOverhead))
	sb.WriteString(fmt.Sprintf("| Memory usage | %.2f MB |\n", r.MemoryUsageMB))
	sb.WriteString(fmt.Sprintf("| Event drop rate | %.2f%% |\n", r.EventDropRate))

	sb.WriteString("\n## Detection Accuracy\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	total := r.TruePositives + r.FalsePositives + r.TrueNegatives + r.FalseNegatives
	sb.WriteString(fmt.Sprintf("| Dataset size | %d |\n", total))
	sb.WriteString(fmt.Sprintf("| True positives | %d |\n", r.TruePositives))
	sb.WriteString(fmt.Sprintf("| False positives | %d |\n", r.FalsePositives))
	sb.WriteString(fmt.Sprintf("| True negatives | %d |\n", r.TrueNegatives))
	sb.WriteString(fmt.Sprintf("| False negatives | %d |\n", r.FalseNegatives))
	sb.WriteString(fmt.Sprintf("| Accuracy | %.2f%% |\n", r.Accuracy*100))
	sb.WriteString(fmt.Sprintf("| Precision | %.2f%% |\n", r.Precision*100))
	sb.WriteString(fmt.Sprintf("| Recall | %.2f%% |\n", r.Recall*100))
	sb.WriteString(fmt.Sprintf("| F1 score | %.2f%% |\n", r.F1Score*100))
	sb.WriteString(fmt.Sprintf("| FP rate | %.2f%% |\n", r.FPRate*100))

	sb.WriteString("\n## External Service Benchmarks\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| ES indexing throughput | %s |\n", r.ESIndexingThroughput))
	sb.WriteString(fmt.Sprintf("| Ollama embedding latency | %s |\n", r.OllamaEmbedLatency))
	sb.WriteString(fmt.Sprintf("| Ollama generation latency | %s |\n", r.OllamaGenLatency))

	sb.WriteString("\n## System Info\n\n")
	sb.WriteString("| Property | Value |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Go version | %s |\n", runtime.Version()))
	sb.WriteString(fmt.Sprintf("| Num CPU | %d |\n", runtime.NumCPU()))
	sb.WriteString(fmt.Sprintf("| GOMAXPROCS | %d |\n", runtime.GOMAXPROCS(0)))
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	sb.WriteString(fmt.Sprintf("| Total alloc | %.2f MB |\n", float64(m.TotalAlloc)/1024/1024))
	sb.WriteString(fmt.Sprintf("| Heap alloc | %.2f MB |\n", float64(m.HeapAlloc)/1024/1024))
	sb.WriteString(fmt.Sprintf("| Sys | %.2f MB |\n", float64(m.Sys)/1024/1024))
	sb.WriteString(fmt.Sprintf("| GC cycles | %d |\n", m.NumGC))

	return sb.String()
}

func (r *BenchReport) WriteFile(path string) error {
	return os.WriteFile(path, []byte(r.ToMarkdown()), 0644)
}
