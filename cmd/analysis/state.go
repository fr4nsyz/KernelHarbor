package main

import "KernelHarbor/cmd/analysis/internal/llm"

var (
	processor   *BatchProcessor
	actionStore = NewActionStore()
	llmBackend  llm.Backend
)
