package main

import "testing"

func TestWorthLLMReview(t *testing.T) {
	tests := []struct {
		name string
		e    Event
		want bool
	}{
		{"execve always", Event{EventType: EventTypeExecve, ImagePath: "/usr/bin/ls"}, true},
		{"execveat always", Event{EventType: EventTypeExecveat}, true},
		{"connect always", Event{EventType: EventTypeConnect, RemoteAddr: "10.0.0.1"}, true},
		{"network always", Event{EventType: EventTypeNetwork}, true},
		{"open library skipped", Event{EventType: EventTypeOpen, FilePath: "/usr/lib/x86_64-linux-gnu/libc.so.6"}, false},
		{"openat proc skipped", Event{EventType: EventTypeOpenat, FilePath: "/proc/self/stat"}, false},
		{"open empty path skipped", Event{EventType: EventTypeOpen}, false},
		{"open ld cache skipped", Event{EventType: EventTypeOpen, FilePath: "/etc/ld.so.cache"}, false},
		{"open localtime skipped", Event{EventType: EventTypeOpenat, FilePath: "/etc/localtime"}, false},
		{"open shadow kept", Event{EventType: EventTypeOpen, FilePath: "/etc/shadow"}, true},
		{"open ld preload kept", Event{EventType: EventTypeOpenat, FilePath: "/etc/ld.so.preload"}, true},
		{"open cron kept", Event{EventType: EventTypeOpenat, FilePath: "/var/spool/cron/crontabs/root"}, true},
		{"open user ssh kept", Event{EventType: EventTypeOpenat, FilePath: "/home/alice/.ssh/id_ed25519"}, true},
		{"open root home kept", Event{EventType: EventTypeOpen, FilePath: "/root/.bash_history"}, true},
		{"open tmp kept", Event{EventType: EventTypeOpenat, FilePath: "/tmp/x.sh"}, true},
		{"open dev shm kept", Event{EventType: EventTypeOpenat, FilePath: "/dev/shm/payload"}, true},
		{"unknown type kept", Event{EventType: "something-new"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := worthLLMReview(tt.e); got != tt.want {
				t.Errorf("worthLLMReview(%+v) = %v, want %v", tt.e, got, tt.want)
			}
		})
	}
}
