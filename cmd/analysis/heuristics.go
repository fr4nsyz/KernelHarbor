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

// hasHeuristicSignal reports whether an event trips a heuristic or
// correlation rule without mutating any caches.
func hasHeuristicSignal(event *Event) bool {
	if processCache != nil {
		if r := evaluateHeuristic(*event, processCache); r.Matched {
			return true
		}
	}
	if correlator != nil {
		return correlator.Evaluate(event.ProcessGUID) != nil
	}
	return false
}

// parseGUIDStartTime extracts the process start-time (ns) suffix from a
// process GUID of the form <host>-<pid>-<start_ns>. Hostnames may contain
// dashes, so we only rely on the last two dash-separated segments.
func parseGUIDStartTime(guid string) (uint64, bool) {
	if guid == "" {
		return 0, false
	}
	idx := strings.LastIndex(guid, "-")
	if idx < 0 || idx == len(guid)-1 {
		return 0, false
	}
	startNs, err := strconv.ParseUint(guid[idx+1:], 10, 64)
	if err != nil {
		return 0, false
	}
	return startNs, true
}

// killPIDTarget builds a "<pid>@<start_ns>" target so the agent can guard
// against PID reuse before sending SIGKILL. Falls back to bare pid when the
// event has no usable start-time (e.g. synthetic/HTTP events without a GUID).
func killPIDTarget(event Event) string {
	base := strconv.Itoa(int(event.ProcessID))
	if startNs, ok := parseGUIDStartTime(event.ProcessGUID); ok {
		return fmt.Sprintf("%s@%d", base, startNs)
	}
	return base
}

type HeuristicResult struct {
	Matched    bool
	Confidence float32
	Category   string
	Reason     string
	Actions    []Action
}

var (
	sensitiveFileRegexps []*regexp.Regexp
	cronPatterns         []*regexp.Regexp
)

func init() {
	cronPatterns = []*regexp.Regexp{
		regexp.MustCompile(`crontab\s+-e`),
		regexp.MustCompile(`crontab\s+-l`),
		regexp.MustCompile(`>\s*/etc/cron`),
		regexp.MustCompile(`>\s*/var/spool/cron`),
		regexp.MustCompile(`echo\s+.*>\s*/etc/cron`),
		regexp.MustCompile(`cat\s+.*\s*>>?\s*/etc/cron`),
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

	for _, rule := range DefaultRules.CommandRules {
		if rule.Pattern.MatchString(query) {
			result.Matched = true
			result.Confidence = rule.Score
			result.Category = rule.Category
			result.Reason = fmt.Sprintf("%s: %s", rule.Category, truncateStr(query, 80))
			result.Actions = append(result.Actions, Action{
				ID:         generateEventID(),
				Timestamp:  event.Timestamp,
				HostName:   event.HostName,
				ActionType: rule.ActionType,
				Target:     killPIDTarget(event),
				Reason:     result.Reason,
			})
			break
		}
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
			Target:     killPIDTarget(event),
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

	for _, rule := range DefaultRules.FileRules {
		if rule.Pattern.MatchString(path) {
			if rule.IsWrite && !isWrite {
				continue
			}
			actionType := rule.ActionType
			if !rule.IsWrite {
				actionType = rule.ReadAction
			}
			result.Matched = true
			result.Confidence = rule.Score
			result.Category = rule.Category
			result.Reason = fmt.Sprintf("%s: %s (flags: %s)", rule.Category, path, event.FileFlags)
			result.Actions = append(result.Actions, Action{
				ID:         generateEventID(),
				Timestamp:  event.Timestamp,
				HostName:   event.HostName,
				ActionType: actionType,
				Target:     killPIDTarget(event),
				Reason:     result.Reason,
			})
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
				ActionType: ActionAlert,
				Target:     killPIDTarget(event),
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

	for _, rule := range DefaultRules.NetworkRules {
		if rule.Port == port {
			result.Matched = true
			result.Confidence = rule.Score
			result.Category = rule.Category
			result.Reason = fmt.Sprintf("%s: port %d (%s) to %s", rule.Category, port, rule.Reason, event.RemoteAddr)
			result.Actions = append(result.Actions, Action{
				ID:         generateEventID(),
				Timestamp:  event.Timestamp,
				HostName:   event.HostName,
				ActionType: rule.ActionType,
				Target:     event.RemoteAddr,
				Reason:     result.Reason,
			})
			break
		}
	}

	if cache != nil {
		if parent, ok := cache.Get(event.ParentGUID); ok {
			parentName := extractBinaryName(parent.ImagePath)
			if DefaultRules.ServerProcesses[parentName] {
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
					ActionType: ActionAlert,
					Target:     killPIDTarget(event),
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

	if DefaultRules.ServerProcesses[parentName] && DefaultRules.ShellImages[childName] {
		allowed := false
		for _, rule := range DefaultRules.Allowlists {
			if rule.Parent == parentName && rule.Child == childName {
				allowed = true
				break
			}
		}

		if !allowed {
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
				Target:     killPIDTarget(event),
				Reason:     result.Reason,
			})
		}
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
