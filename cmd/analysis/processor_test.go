package main

import (
	"reflect"
	"testing"
	"time"
)

func TestDecideAIActionsNeverEscalatesAlertOnlyHeuristicToKill(t *testing.T) {
	ev := Event{EventID: "p", EventType: EventTypeOpen, FilePath: "/etc/passwd", FileFlags: "O_RDONLY",
		ProcessID: 42, HostName: "h", Timestamp: time.Now()}
	batch := Batch{HostName: "h", Events: []Event{ev}}
	for _, a := range decideAIActions(batch, "malicious", 0.95, "s", []string{"p"}) {
		if a.ActionType != ActionAlert {
			t.Errorf("got %s for alert-only /etc/passwd read, want only ALERT", a.ActionType)
		}
	}
}

func TestDecideAIActions(t *testing.T) {
	batch := Batch{
		HostName: "h",
		Events: []Event{
			{EventID: "exec", EventType: EventTypeExecve, ProcessID: 10},
			{EventID: "conn", EventType: EventTypeConnect, ProcessID: 30, RemoteAddr: "203.0.113.5", RemotePort: 4444},
		},
	}

	type act struct {
		Type   ActionType
		Target string
	}
	tests := []struct {
		name       string
		verdict    string
		confidence float64
		flagged    []string
		want       []act
	}{
		{"flagged event only alerts", "malicious", 0.9, []string{"exec"},
			[]act{{ActionAlert, "10"}}},
		{"flagged connect alerts without blocking", "malicious", 0.9, []string{"conn"},
			[]act{{ActionAlert, "30"}}},
		{"low confidence does nothing", "malicious", 0.6, []string{"exec"}, nil},
		{"suspicious verdict does nothing", "suspicious", 0.9, []string{"exec"}, nil},
		{"unknown id does nothing", "malicious", 0.9, []string{"ghost"}, nil},
		{"no ids alerts on every event", "malicious", 0.9, nil,
			[]act{{ActionAlert, "10"}, {ActionAlert, "30"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []act
			for _, a := range decideAIActions(batch, tt.verdict, tt.confidence, "s", tt.flagged) {
				got = append(got, act{a.ActionType, a.Target})
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
