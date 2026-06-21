package main

import (
	"sync"
	"time"
)

type Alert struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	HostName   string    `json:"host.name"`
	Verdict    string    `json:"verdict"`
	Confidence float64   `json:"confidence"`
	Evidence   []string  `json:"evidence"`
	Summary    string    `json:"summary"`
	ModelUsed  string    `json:"model.used,omitempty"`
	Feedback   string    `json:"feedback,omitempty"`
	Events     []Event   `json:"events,omitempty"`
	Source     string    `json:"source"` // "heuristic" or "llm"
}

type AlertStore struct {
	mu     sync.RWMutex
	alerts []Alert
}

func NewAlertStore() *AlertStore {
	return &AlertStore{}
}

func (as *AlertStore) Add(alert Alert) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.alerts = append(as.alerts, alert)
	if len(as.alerts) > 10000 {
		as.alerts = as.alerts[len(as.alerts)-5000:]
	}
}

func (as *AlertStore) List(since time.Time, minVerdict string, limit int) []Alert {
	as.mu.RLock()
	defer as.mu.RUnlock()

	severityOrder := map[string]int{
		"benign":     0,
		"suspicious": 1,
		"malicious":  2,
	}

	minOrder := severityOrder[minVerdict]
	if minOrder == 0 && minVerdict != "benign" {
		minOrder = 0
	}

	var result []Alert
	for i := len(as.alerts) - 1; i >= 0 && len(result) < limit; i-- {
		a := as.alerts[i]
		if !a.Timestamp.Before(since) {
			if severityOrder[a.Verdict] >= minOrder {
				result = append(result, a)
			}
		}
	}

	return result
}

func (as *AlertStore) SetFeedback(id, feedback string) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	for i := range as.alerts {
		if as.alerts[i].ID == id {
			as.alerts[i].Feedback = feedback
			return true
		}
	}
	return false
}

func (as *AlertStore) Stats() AlertStats {
	as.mu.RLock()
	defer as.mu.RUnlock()

	var stats AlertStats
	seen := time.Now().Add(-24 * time.Hour)

	for _, a := range as.alerts {
		if !a.Timestamp.Before(seen) {
			stats.Alerts24h++
		}
		switch a.Verdict {
		case "malicious":
			stats.Malicious++
		case "suspicious":
			stats.Suspicious++
		}
		if a.Feedback == "confirmed" {
			stats.Confirmed++
		} else if a.Feedback == "false_positive" {
			stats.FalsePositives++
		}
	}
	return stats
}

type AlertStats struct {
	Alerts24h      int `json:"alerts_24h"`
	Malicious      int `json:"malicious"`
	Suspicious     int `json:"suspicious"`
	Confirmed      int `json:"confirmed"`
	FalsePositives int `json:"false_positives"`
}
