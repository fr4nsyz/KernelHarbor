package main

import "time"

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

	SocketInfo string `json:"socket.info,omitempty"`
	RemoteAddr string `json:"remote.address,omitempty"`
	RemotePort uint16 `json:"remote.port,omitempty"`

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

	if isLOLBin(img) {
		behaviors = append(behaviors, "lolbin")
	}

	if containsAny(cmd, []string{"curl", "wget", "fetch"}) && containsAny(cmd, []string{"|", "&&", ";", "bash", "sh", "python"}) {
		behaviors = append(behaviors, "remote_code_execution")
	}

	if containsAny(cmd, []string{"powershell", "ps1", "-enc", "-e ", "IEX"}) {
		behaviors = append(behaviors, "powershell_obfuscation")
	}

	if containsAny(cmd, []string{"base64", "-enc", "frombase64", "decode"}) {
		behaviors = append(behaviors, "encoded_command")
	}

	if containsAny(cmd, []string{"/tmp", "/var/tmp", "C:\\Users\\Temp", "AppData\\Local\\Temp"}) {
		behaviors = append(behaviors, "temp_directory_execution")
	}

	if cmd == "" && e.FilePath != "" {
		behaviors = append(behaviors, "file_access:"+extractFileType(e.FilePath))
	}

	behaviors = append(behaviors, "user:"+e.User)
	behaviors = append(behaviors, "image:"+extractBinaryName(img))

	return joinNonEmpty(behaviors, " ")
}

func isLOLBin(path string) bool {
	lolbins := []string{
		"powershell.exe", "cmd.exe", "certutil.exe", "rundll32.exe",
		"mshta.exe", "cscript.exe", "wscript.exe", "regsvr32.exe",
		"msiexec.exe", "wmic.exe", "msbuild.exe", "installutil.exe",
		"svchost.exe", "explorer.exe", "notepad.exe",
	}
	lower := toLower(path)
	for _, b := range lolbins {
		if contains(lower, toLower(b)) {
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
