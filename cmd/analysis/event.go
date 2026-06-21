package main

import (
	"sync"
	"time"
)

const (
	EventTypeExecve  = "execve"
	EventTypeOpen    = "open"
	EventTypeProcess = "process"
	EventTypeNetwork = "network"
)

type Event struct {
	Timestamp time.Time `json:"@timestamp"`
	HostName  string    `json:"host.name"`
	EventType string    `json:"event.type"`
	EventID   string    `json:"event.id"`

	ProcessGUID string `json:"process.guid,omitempty"`
	ParentGUID  string `json:"parent.guid,omitempty"`
	ProcessID   uint32 `json:"process.pid,omitempty"`
	ParentPID   uint32 `json:"parent.pid,omitempty"`

	ImagePath   string `json:"image.path,omitempty"`
	CommandLine string `json:"command.line,omitempty"`
	WorkingDir  string `json:"working.directory,omitempty"`
	User        string `json:"user.name,omitempty"`

	FilePath  string `json:"file.path,omitempty"`
	FileFlags string `json:"file.flags,omitempty"`
	FileMode  uint32 `json:"file.mode,omitempty"`

	SocketInfo string `json:"socket.info,omitempty"`
	RemoteAddr string `json:"remote.address,omitempty"`
	RemotePort uint16 `json:"remote.port,omitempty"`
	LocalAddr  string `json:"local.address,omitempty"`
	LocalPort  uint16 `json:"local.port,omitempty"`

	Metadata map[string]any `json:"metadata,omitempty"`

	Embedding []float32 `json:"embedding,omitempty"`
}

type EventBatch struct {
	Events     []Event   `json:"events"`
	HostName   string    `json:"host.name"`
	ReceivedAt time.Time `json:"received.at"`
}

type AnalysisResult struct {
	EventID     string    `json:"event.id"`
	Timestamp   time.Time `json:"timestamp"`
	HostName    string    `json:"host.name"`
	Verdict     string    `json:"verdict"`
	Confidence  float64   `json:"confidence"`
	Evidence    []string  `json:"evidence"`
	Summary     string    `json:"summary"`
	RawResponse string    `json:"raw.response,omitempty"`
}

func (e *Event) ToSearchText() string {
	var parts []string
	if e.EventType != "" {
		parts = append(parts, e.EventType)
	}
	if e.ImagePath != "" {
		parts = append(parts, "image:"+e.ImagePath)
	}
	if e.CommandLine != "" {
		parts = append(parts, "cmd:"+e.CommandLine)
	}
	if e.FilePath != "" {
		parts = append(parts, "file:"+e.FilePath)
	}
	if e.User != "" {
		parts = append(parts, "user:"+e.User)
	}
	if e.ParentGUID != "" {
		parts = append(parts, "parent:"+e.ParentGUID)
	}
	return joinNonEmpty(parts, " ")
}

func (e *Event) ToBehaviorSummary() string {
	var behaviors []string

	behaviors = append(behaviors, "event_type:"+e.EventType)

	cmd := e.CommandLine
	img := e.ImagePath

	if isReverseShell(img, cmd) {
		behaviors = append(behaviors, "reverse_shell")
	}

	if containsAny(cmd, []string{"curl", "wget", "fetch"}) &&
		containsAny(cmd, []string{"|", "&&", ";", "bash", "sh", "python", "python3"}) {
		behaviors = append(behaviors, "remote_code_execution")
	}

	if containsAny(cmd, []string{"base64", "-enc", "-d", "frombase64", "decode"}) {
		behaviors = append(behaviors, "encoded_command")
	}

	if containsAny(img, []string{"/tmp", "/var/tmp", "/dev/shm"}) {
		behaviors = append(behaviors, "temp_directory_execution")
	}

	if e.EventType == "connect" && e.RemoteAddr != "" {
		portStr := ""
		if e.RemotePort > 0 {
			portStr = fmtPort(e.RemotePort)
		}
		behaviors = append(behaviors, "remote:"+obfuscateIP(e.RemoteAddr)+portStr)
	}

	if e.EventType == "open" || e.EventType == "openat" {
		if e.FilePath != "" {
			behaviors = append(behaviors, "file:"+e.FilePath)
		}
	}

	if containsAny(img, []string{"nc", "netcat", "ncat", "socat"}) {
		behaviors = append(behaviors, "network_tool")
	}

	if e.ParentGUID != "" {
		behaviors = append(behaviors, "parent_guid:"+e.ParentGUID)
	}

	if cmd == "" && e.FilePath != "" {
		behaviors = append(behaviors, "file_access:"+extractFileType(e.FilePath))
	}

	behaviors = append(behaviors, "user:"+e.User)
	behaviors = append(behaviors, "image:"+extractBinaryName(img))

	return joinNonEmpty(behaviors, " ")
}

func isReverseShell(img, cmd string) bool {
	cmdLower := toLower(cmd)
	imgLower := toLower(img)

	if containsAny(cmdLower, []string{"/dev/tcp", "/dev/udp", ">&1", "0>&1", ">&0", "2>&1", "<&1"}) {
		return true
	}

	reverseShellPatterns := []string{
		"bash -i",
		"sh -i",
		"/bin/bash -i",
		"/bin/sh -i",
		"nc -e",
		"ncat -e",
		"socat exec",
	}

	for _, pattern := range reverseShellPatterns {
		if contains(cmdLower, pattern) {
			return true
		}
	}

	if contains(imgLower, "perl") && contains(cmdLower, "socket") {
		return true
	}

	if contains(imgLower, "python") || contains(imgLower, "python3") {
		if containsAny(cmdLower, []string{"socket", "subprocess", "pty.spawn", "popen"}) {
			return true
		}
	}

	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		if contains(s, sub) {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

func extractBinaryName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return toLower(path[i+1:])
		}
	}
	return toLower(path)
}

func extractFileType(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return toLower(path[i+1:])
		}
	}
	return "unknown"
}

type ActionType string

const (
	ActionKillPID ActionType = "KILL_PID"
	ActionBlockIP ActionType = "BLOCK_IP"
)

type Action struct {
	ID         string     `json:"id"`
	Timestamp  time.Time  `json:"timestamp"`
	HostName   string     `json:"host.name"`
	ActionType ActionType `json:"action.type"`
	Target     string     `json:"target"`
	Reason     string     `json:"reason"`
}

type ActionStore struct {
	mu      sync.Mutex
	actions map[string][]Action
}

func NewActionStore() *ActionStore {
	return &ActionStore{actions: make(map[string][]Action)}
}

func (s *ActionStore) Add(hostname string, action Action) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actions[hostname] = append(s.actions[hostname], action)
}

func (s *ActionStore) Fetch(hostname string) []Action {
	s.mu.Lock()
	defer s.mu.Unlock()
	actions := s.actions[hostname]
	delete(s.actions, hostname)
	return actions
}

func fmtPort(port uint16) string {
	if port == 80 || port == 443 {
		return ":http"
	}
	if port == 22 {
		return ":ssh"
	}
	if port == 53 {
		return ":dns"
	}
	return ":" + itoaU16(port)
}

func itoaU16(n uint16) string {
	if n == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func obfuscateIP(addr string) string {
	if len(addr) >= 8 {
		return addr[:min(8, len(addr))] + "..."
	}
	return addr
}

func joinNonEmpty(s []string, sep string) string {
	result := ""
	for i, v := range s {
		if v != "" {
			if i > 0 {
				result += sep
			}
			result += v
		}
	}
	return result
}
