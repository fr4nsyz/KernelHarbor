package main

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	processCache = NewProcessCache(10000)
	correlator   = NewCorrelator(30*time.Second, 100)
)

func processEvent(event *Event) []Action {
	result := evaluateHeuristic(*event, processCache)

	if result.Matched {
		log.Printf("Heuristic match [%s] PID=%d confidence=%.2f: %s",
			result.Category, event.ProcessID, result.Confidence, result.Reason)
	}

	processCache.RecordHeuristicScore(*event, result.Confidence)
	correlator.Add(*event)

	if chain := correlator.Evaluate(event.ProcessGUID); chain != nil && chain.Score >= 0.6 {
		log.Printf("Correlation chain detected for %s: score=%.2f verdict=%s chains=%v",
			event.ProcessGUID, chain.Score, chain.Verdict, chain.ChainDesc)
		result.Actions = append(result.Actions, chain.Actions...)
		if chain.Score > float64(result.Confidence) {
			result.Confidence = float32(chain.Score)
			result.Reason = fmt.Sprintf("correlated: %s", strings.Join(chain.Evidence, "; "))
		}
	}

	return result.Actions
}

type HeuristicResult struct {
	Matched    bool
	Confidence float32
	Category   string
	Reason     string
	Actions    []Action
}

type heuristicRule struct {
	pattern  *regexp.Regexp
	category string
	score    float32
}

var (
	sensitiveFilePaths = []string{
		`/etc/shadow`,
		`/etc/passwd`,
		`/etc/sudoers`,
		`/etc/crontab`,
		`/etc/cron\.d/`,
		`/etc/ssh/sshd_config`,
		`/etc/pam\.d/`,
		`/etc/selinux/`,
		`/etc/apparmor/`,
		`/etc/security/`,
		`/etc/login\.defs`,
		`/var/spool/cron/`,
		`/var/log/auth\.log`,
		`/var/log/syslog`,
		`\.ssh/authorized_keys`,
		`\.ssh/id_rsa`,
		`\.ssh/config`,
		`\.gnupg/`,
		`/boot/grub/`,
		`/etc/ld\.so\.preload`,
		`/etc/ld\.so\.conf`,
		`/etc/environment`,
		`/etc/profile`,
		`/etc/bash\.bashrc`,
	}

	sensitiveFileRegexps []*regexp.Regexp

	suspiciousPorts = map[uint16]string{
		4444:  "netcat/metasploit default",
		5555:  "android debug / common C2",
		6666:  "irc backdoor / common C2",
		7777:  "common backdoor",
		8888:  "common proxy/C2",
		1234:  "common test/backdoor port",
		31337: "Back Orifice",
		12345: "netbus trojan",
		54321: "Back Orifice 2000",
		9999:  "common C2",
		44344: "common C2",
		8080:  "alt HTTP (suspicious from non-web)",
		8443:  "alt HTTPS (suspicious from non-web)",
		1080:  "SOCKS proxy",
		9050:  "Tor SOCKS",
		6697:  "IRC over SSL",
	}

	serverProcesses = map[string]bool{
		"nginx":           true,
		"apache2":         true,
		"httpd":           true,
		"sshd":            true,
		"mysqld":          true,
		"postgres":        true,
		"postgresql":      true,
		"redis-server":    true,
		"mongod":          true,
		"php-fpm":         true,
		"java":            true,
		"docker":          true,
		"containerd-shim": true,
		"kubelet":         true,
		"node_exporter":   true,
		"prometheus":      true,
		"elastic-agent":   true,
		"filebeat":        true,
		"logstash":        true,
		"cron":            true,
		"systemd-network": true,
		"dbus-daemon":     true,
	}

	shellImages = map[string]bool{
		"bash":      true,
		"sh":        true,
		"dash":      true,
		"zsh":       true,
		"ksh":       true,
		"csh":       true,
		"tcsh":      true,
		"fish":      true,
		"/bin/bash": true,
		"/bin/sh":   true,
		"/bin/dash": true,
		"/bin/zsh":  true,
	}

	cronPatterns = []*regexp.Regexp{
		regexp.MustCompile(`crontab\s+-e`),
		regexp.MustCompile(`crontab\s+-l`),
		regexp.MustCompile(`>\s*/etc/cron`),
		regexp.MustCompile(`>\s*/var/spool/cron`),
		regexp.MustCompile(`echo\s+.*>\s*/etc/cron`),
		regexp.MustCompile(`cat\s+.*\s*>>?\s*/etc/cron`),
	}
)

func init() {
	for _, p := range sensitiveFilePaths {
		sensitiveFileRegexps = append(sensitiveFileRegexps, regexp.MustCompile(p))
	}
}

func evaluateHeuristic(event Event, cache *ProcessCache) HeuristicResult {
	switch event.EventType {
	case EventTypeOpen, "openat":
		return evaluateFileHeuristic(event, cache)
	case EventTypeNetwork, "connect":
		return evaluateNetworkHeuristic(event, cache)
	case EventTypeExecve, "execveat":
		return evaluateCommandHeuristic(event, cache)
	default:
		return HeuristicResult{Confidence: 0.0}
	}
}

func evaluateCommandHeuristic(event Event, cache *ProcessCache) HeuristicResult {
	result := HeuristicResult{
		Category: "command",
	}

	cmd := event.CommandLine
	img := event.ImagePath

	if cmd == "" && img == "" {
		return result
	}

	query := cmd
	if query == "" {
		query = img
	}

	if hasSuspiciousPattern(query) {
		result.Matched = true
		result.Confidence = 0.7
		result.Reason = fmt.Sprintf("suspicious command pattern: %s", truncateStr(query, 80))
		result.Actions = append(result.Actions, Action{
			ID:         generateEventID(),
			Timestamp:  event.Timestamp,
			HostName:   event.HostName,
			ActionType: ActionKillPID,
			Target:     strconv.Itoa(int(event.ProcessID)),
			Reason:     result.Reason,
		})
	}

	if isCronTampering(cmd) {
		if !result.Matched {
			result.Matched = true
			result.Confidence = 0.6
		}
		result.Confidence = maxF32(result.Confidence, 0.6)
		if result.Reason == "" {
			result.Reason = "cron tampering detected"
		} else {
			result.Reason += "; cron tampering detected"
		}
		result.Actions = append(result.Actions, Action{
			ID:         generateEventID(),
			Timestamp:  event.Timestamp,
			HostName:   event.HostName,
			ActionType: ActionKillPID,
			Target:     strconv.Itoa(int(event.ProcessID)),
			Reason:     "cron tampering: modifying cron configuration",
		})
	}

	if cache != nil {
		result = applyProcessContext(result, event, cache)
	}

	return result
}

func evaluateFileHeuristic(event Event, cache *ProcessCache) HeuristicResult {
	result := HeuristicResult{
		Category: "file_access",
	}

	path := event.FilePath
	if path == "" {
		return result
	}

	isWrite := strings.Contains(event.FileFlags, "O_WRONLY") ||
		strings.Contains(event.FileFlags, "O_RDWR") ||
		strings.Contains(event.FileFlags, "O_CREAT")
	isCreate := strings.Contains(event.FileFlags, "O_CREAT")

	for _, re := range sensitiveFileRegexps {
		if re.MatchString(path) {
			if isWrite {
				result.Matched = true
				result.Confidence = 0.9
				result.Reason = fmt.Sprintf("write to sensitive file: %s (flags: %s)", path, event.FileFlags)
				result.Actions = append(result.Actions, Action{
					ID:         generateEventID(),
					Timestamp:  event.Timestamp,
					HostName:   event.HostName,
					ActionType: ActionKillPID,
					Target:     strconv.Itoa(int(event.ProcessID)),
					Reason:     result.Reason,
				})
				break
			}
			result.Matched = true
			result.Confidence = 0.4
			result.Reason = fmt.Sprintf("read access to sensitive file: %s", path)
			break
		}
	}

	if isCreate && isTempPath(path) {
		if !result.Matched || result.Confidence < 0.5 {
			result.Matched = true
			result.Confidence = maxF32(result.Confidence, 0.5)
			result.Reason = fmt.Sprintf("file creation in temp directory: %s", path)
		}
	}

	if isWrite && isLogPath(path) {
		if !result.Matched || result.Confidence < 0.7 {
			result.Matched = true
			result.Confidence = maxF32(result.Confidence, 0.7)
			result.Reason = fmt.Sprintf("write to log file (possible tampering): %s", path)
			result.Actions = append(result.Actions, Action{
				ID:         generateEventID(),
				Timestamp:  event.Timestamp,
				HostName:   event.HostName,
				ActionType: ActionKillPID,
				Target:     strconv.Itoa(int(event.ProcessID)),
				Reason:     result.Reason,
			})
		}
	}

	if cache != nil {
		result = applyProcessContext(result, event, cache)
	}

	return result
}

func evaluateNetworkHeuristic(event Event, cache *ProcessCache) HeuristicResult {
	result := HeuristicResult{
		Category: "network",
	}

	port := event.RemotePort
	if port == 0 {
		return result
	}

	if reason, ok := suspiciousPorts[port]; ok {
		result.Matched = true
		result.Confidence = 0.6
		result.Reason = fmt.Sprintf("connection to suspicious port %d (%s) to %s", port, reason, event.RemoteAddr)
		result.Actions = append(result.Actions, Action{
			ID:         generateEventID(),
			Timestamp:  event.Timestamp,
			HostName:   event.HostName,
			ActionType: ActionBlockIP,
			Target:     event.RemoteAddr,
			Reason:     result.Reason,
		})
	}

	if cache != nil {
		if parent, ok := cache.Get(event.ParentGUID); ok {
			parentName := extractBinaryName(parent.ImagePath)
			if serverProcesses[parentName] {
				if !result.Matched {
					result.Matched = true
					result.Confidence = 0.5
				}
				result.Confidence = maxF32(result.Confidence, 0.5)
				result.Reason = fmt.Sprintf("network connection from server process %s (PID %d) to %s:%d",
					parentName, parent.PID, event.RemoteAddr, port)
				result.Actions = append(result.Actions, Action{
					ID:         generateEventID(),
					Timestamp:  event.Timestamp,
					HostName:   event.HostName,
					ActionType: ActionBlockIP,
					Target:     event.RemoteAddr,
					Reason:     result.Reason,
				})
			}
		}

		result = applyProcessContext(result, event, cache)
	}

	return result
}

func applyProcessContext(result HeuristicResult, event Event, cache *ProcessCache) HeuristicResult {
	parent, ok := cache.Get(event.ParentGUID)
	if !ok {
		return result
	}

	parentName := extractBinaryName(parent.ImagePath)
	childName := extractBinaryName(event.ImagePath)

	if serverProcesses[parentName] && shellImages[childName] {
		if !result.Matched {
			result.Matched = true
			result.Confidence = 0.7
		}
		result.Confidence = maxF32(result.Confidence, 0.7)
		result.Reason = fmt.Sprintf("service %s spawned shell %s (PID %d)", parentName, childName, event.ProcessID)
		result.Actions = append(result.Actions, Action{
			ID:         generateEventID(),
			Timestamp:  event.Timestamp,
			HostName:   event.HostName,
			ActionType: ActionKillPID,
			Target:     strconv.Itoa(int(event.ProcessID)),
			Reason:     result.Reason,
		})
	}

	if parent.HeuristicScore > 0.5 && result.Confidence > 0 {
		compounded := 1.0 - (1.0-float64(result.Confidence))*(1.0-float64(parent.HeuristicScore))
		result.Confidence = float32(compounded)
		result.Reason = fmt.Sprintf("%s (parent %s previously scored %.2f)", result.Reason, parentName, parent.HeuristicScore)
	}

	return result
}

func isCronTampering(cmd string) bool {
	if cmd == "" {
		return false
	}
	for _, re := range cronPatterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

func isTempPath(path string) bool {
	return strings.HasPrefix(path, "/tmp") ||
		strings.HasPrefix(path, "/var/tmp") ||
		strings.HasPrefix(path, "/dev/shm")
}

func isLogPath(path string) bool {
	return strings.HasPrefix(path, "/var/log/") ||
		strings.Contains(path, "/logs/")
}

func maxF32(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}

func truncateStr(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-3]) + "..."
}
