package main

import (
	"context"
	"log"
	"time"

	"KernelHarbor/cmd/analysis/internal/incidents"
	"KernelHarbor/cmd/analysis/internal/llm"
)

var (
	processor     *BatchProcessor
	actionStore   = NewActionStore()
	alertStore    *AlertStore
	incidentStore *incidents.Store
	llmBackend    llm.Backend
)

type heuristicEventLike struct {
	eventType   string
	commandLine string
	imagePath   string
}

func (e heuristicEventLike) GetEventType() string   { return e.eventType }
func (e heuristicEventLike) GetCommandLine() string { return e.commandLine }
func (e heuristicEventLike) GetImagePath() string   { return e.imagePath }

func addHeuristicAlert(event Event) {
	if alertStore == nil {
		return
	}
	query := event.CommandLine
	if query == "" {
		query = event.FilePath
	}
	if query == "" {
		query = event.RemoteAddr
	}
	alertID := generateEventID()
	alert := Alert{
		ID:         alertID,
		Timestamp:  time.Now(),
		HostName:   event.HostName,
		Verdict:    "suspicious",
		Confidence: 0.7,
		Evidence:   []string{query},
		Summary:    "Heuristic match: " + query,
		Source:     "heuristic",
	}
	alertStore.Add(alert)
	if esClientInstance != nil {
		if err := esClientInstance.IndexAlert(context.Background(), alert); err != nil {
			log.Printf("Failed to index alert to ES: %v", err)
		}
	}
	if incidentStore != nil {
		incidentStore.Add(&incidents.Incident{
			ID: alertID,
			Events: []incidents.EventLike{
				heuristicEventLike{
					eventType:   event.EventType,
					commandLine: event.CommandLine,
					imagePath:   event.ImagePath,
				},
			},
			Verdict:    "suspicious",
			IsVerified: false,
			Summary:    "Heuristic match: " + query,
			CreatedAt:  time.Now(),
		})
	}
}
