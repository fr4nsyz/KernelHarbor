package main

import (
	"context"
	"testing"
	"time"
)

func TestClassifyEventsSkipsWhenClassifierDisabled(t *testing.T) {
	previous := classifier
	t.Cleanup(func() { classifier = previous })

	classifier = NewClassifier(nil, 0.5, 1)

	batch := Batch{Events: []Event{unclassifiedExecve()}}
	bp := &BatchProcessor{ctx: context.Background()}

	bp.classifyEvents(context.Background(), batch)

	if batch.Events[0].Category != CategoryCommand {
		t.Errorf("category = %q, want %q", batch.Events[0].Category, CategoryCommand)
	}
}

func TestClassifyEventsClassifiesBatchInParallel(t *testing.T) {
	previous := classifier
	previousES := esClientInstance
	t.Cleanup(func() {
		classifier = previous
		esClientInstance = previousES
	})
	esClientInstance = nil

	stub := &layaStub{}
	client := newClassifierServer(t, stub,
		LayaAnswer{Type: "choice", Choice: TacticExecution, Confidence: 0.9},
		LayaAnswer{Type: "choice", Choice: "reverse_shell", Confidence: 0.75},
	)
	classifier = NewClassifier(client, 0.5, 4)

	batch := Batch{HostName: "host-1", Events: []Event{
		unclassifiedExecve(),
		unclassifiedExecve(),
		unclassifiedExecve(),
	}}
	batch.Events[1].EventID = "evt-2"
	batch.Events[2].EventID = "evt-3"

	bp := &BatchProcessor{ctx: context.Background()}
	bp.classifyEvents(context.Background(), batch)

	for i, event := range batch.Events {
		if event.Category != "reverse_shell" {
			t.Errorf("event %d category = %q, want reverse_shell", i, event.Category)
		}
		if event.Tactic != TacticExecution {
			t.Errorf("event %d tactic = %q, want %s", i, event.Tactic, TacticExecution)
		}
		if event.CategorySource != CategorySourceLaya {
			t.Errorf("event %d source = %q, want %q", i, event.CategorySource, CategorySourceLaya)
		}
	}

	if stub.count() != 6 {
		t.Errorf("expected 6 laya calls (2 stages x 3 events), got %d", stub.count())
	}
}

func TestClassifyEventsLeavesRuleMatchedEventsAlone(t *testing.T) {
	previous := classifier
	previousES := esClientInstance
	t.Cleanup(func() {
		classifier = previous
		esClientInstance = previousES
	})
	esClientInstance = nil

	stub := &layaStub{}
	client := newClassifierServer(t, stub,
		LayaAnswer{Type: "choice", Choice: TacticExecution, Confidence: 0.99},
		LayaAnswer{Type: "choice", Choice: "reverse_shell", Confidence: 0.99},
	)
	classifier = NewClassifier(client, 0, 4)

	event := unclassifiedExecve()
	applyAttackTaxonomy(&event, "curl_pipe", 0.95, CategorySourceRules)
	batch := Batch{Events: []Event{event}}

	bp := &BatchProcessor{ctx: context.Background()}
	bp.classifyEvents(context.Background(), batch)

	if batch.Events[0].Category != "curl_pipe" {
		t.Errorf("category = %q, want curl_pipe", batch.Events[0].Category)
	}
	if stub.count() != 0 {
		t.Errorf("expected no laya calls, got %d", stub.count())
	}
}

func TestClassifyEventsRespectsCancelledContext(t *testing.T) {
	previous := classifier
	previousES := esClientInstance
	t.Cleanup(func() {
		classifier = previous
		esClientInstance = previousES
	})
	esClientInstance = nil

	stub := &layaStub{}
	client := newClassifierServer(t, stub,
		LayaAnswer{Type: "choice", Choice: TacticExecution, Confidence: 0.9},
		LayaAnswer{Type: "choice", Choice: "reverse_shell", Confidence: 0.9},
	)
	classifier = NewClassifier(client, 0.5, 2)

	batch := Batch{Events: []Event{unclassifiedExecve()}}
	bp := &BatchProcessor{ctx: context.Background()}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	cancel()

	bp.classifyEvents(ctx, batch)

	if batch.Events[0].Category != CategoryCommand {
		t.Errorf("category = %q, want the heuristic fallback %q", batch.Events[0].Category, CategoryCommand)
	}
}
