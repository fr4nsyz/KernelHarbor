package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type CorrelationChain struct {
	ProcessGUID string
	Events      []Event
	ChainDesc   []string
	Score       float64
	Verdict     string
	Evidence    []string
	Actions     []Action
}

type chainRule struct {
	name  string
	score float64
	match func(events []Event) (bool, []string)
}

var defaultChainRules = []chainRule{
	{
		name:  "write_then_execute",
		score: 0.8,
		match: func(events []Event) (bool, []string) {
			var wroteToSensitive, executed bool
			var writePath, execImage string
			for _, e := range events {
				if e.EventType == EventTypeOpen || e.EventType == "openat" {
					if isSensitiveWrite(e) {
						wroteToSensitive = true
						writePath = e.FilePath
					}
				}
				if e.EventType == EventTypeExecve || e.EventType == "execveat" {
					executed = true
					execImage = extractBinaryName(e.ImagePath)
				}
			}
			if wroteToSensitive && executed {
				return true, []string{
					fmt.Sprintf("write to %s followed by execve (%s)", writePath, execImage),
				}
			}
			return false, nil
		},
	},
	{
		name:  "download_drop_execute",
		score: 0.85,
		match: func(events []Event) (bool, []string) {
			var hasDownload, hasTempCreate, hasTempExec bool
			var downloadTool, tempPath, execImage string
			for _, e := range events {
				img := extractBinaryName(e.ImagePath)
				cmd := e.CommandLine
				if (img == "curl" || img == "wget" || img == "fetch") &&
					(strings.Contains(cmd, "http://") || strings.Contains(cmd, "https://")) {
					hasDownload = true
					downloadTool = img
				}
				if (e.EventType == EventTypeOpen || e.EventType == "openat") &&
					strings.Contains(e.FileFlags, "O_CREAT") && isTempPath(e.FilePath) {
					hasTempCreate = true
					tempPath = e.FilePath
				}
				if e.EventType == EventTypeExecve || e.EventType == "execveat" {
					if isTempPath(e.ImagePath) ||
						(e.FilePath != "" && isTempPath(extractDir(e.FilePath))) ||
						containsAnyTempPath(e.CommandLine) {
						hasTempExec = true
						execImage = extractBinaryName(e.ImagePath)
					}
				}
			}
			if hasDownload && hasTempCreate && hasTempExec {
				return true, []string{
					fmt.Sprintf("%s downloaded to %s, then executed as %s", downloadTool, tempPath, execImage),
				}
			}
			if hasDownload && hasTempExec {
				return true, []string{
					fmt.Sprintf("%s downloaded and executed from temp: %s", downloadTool, execImage),
				}
			}
			return false, nil
		},
	},
	{
		name:  "exec_then_c2",
		score: 0.7,
		match: func(events []Event) (bool, []string) {
			var hasExec, hasSuspiciousConn bool
			var execImage, connPort string
			for _, e := range events {
				if e.EventType == EventTypeExecve || e.EventType == "execveat" {
					hasExec = true
					execImage = extractBinaryName(e.ImagePath)
				}
				if e.EventType == EventTypeNetwork || e.EventType == "connect" {
					if _, ok := suspiciousPorts[e.RemotePort]; ok {
						hasSuspiciousConn = true
						connPort = fmt.Sprintf("%d", e.RemotePort)
					}
				}
			}
			if hasExec && hasSuspiciousConn {
				return true, []string{
					fmt.Sprintf("execve (%s) followed by connection to suspicious port %s", execImage, connPort),
				}
			}
			return false, nil
		},
	},
	{
		name:  "credential_theft",
		score: 0.9,
		match: func(events []Event) (bool, []string) {
			var hasShadowRead, hasExfil bool
			for _, e := range events {
				if (e.EventType == EventTypeOpen || e.EventType == "openat") &&
					(strings.Contains(e.FilePath, "/etc/shadow") ||
						strings.Contains(e.FilePath, "/etc/passwd")) &&
					!strings.Contains(e.FileFlags, "O_WRONLY") &&
					!strings.Contains(e.FileFlags, "O_RDWR") {
					hasShadowRead = true
				}
				if e.EventType == EventTypeNetwork || e.EventType == "connect" {
					if e.RemotePort != 0 {
						hasExfil = true
					}
				}
			}
			if hasShadowRead && hasExfil {
				return true, []string{"read of sensitive credential file followed by network connection (potential exfiltration)"}
			}
			return false, nil
		},
	},
	{
		name:  "pivot_chain",
		score: 0.85,
		match: func(events []Event) (bool, []string) {
			var connCount, netToolExec int
			for _, e := range events {
				if e.EventType == EventTypeNetwork || e.EventType == "connect" {
					connCount++
				}
				if e.EventType == EventTypeExecve || e.EventType == "execveat" {
					img := extractBinaryName(e.ImagePath)
					if img == "nc" || img == "ncat" || img == "socat" || img == "netcat" {
						netToolExec++
					}
				}
			}
			if netToolExec > 0 && connCount >= 2 {
				return true, []string{
					fmt.Sprintf("network tool executed (%d times) with %d connections (possible pivot)", netToolExec, connCount),
				}
			}
			return false, nil
		},
	},
	{
		name:  "rapid_spawn",
		score: 0.6,
		match: func(events []Event) (bool, []string) {
			execCount := 0
			for _, e := range events {
				if e.EventType == EventTypeExecve || e.EventType == "execveat" {
					execCount++
				}
			}
			if execCount >= 5 {
				return true, []string{
					fmt.Sprintf("%d execve events in correlation window (rapid process spawning)", execCount),
				}
			}
			return false, nil
		},
	},
}

type Correlator struct {
	mu               sync.RWMutex
	processEvents    map[string][]Event
	window           time.Duration
	maxEventsPerProc int
	rules            []chainRule
}

func NewCorrelator(window time.Duration, maxEventsPerProc int) *Correlator {
	if window <= 0 {
		window = 30 * time.Second
	}
	if maxEventsPerProc <= 0 {
		maxEventsPerProc = 100
	}
	return &Correlator{
		processEvents:    make(map[string][]Event),
		window:           window,
		maxEventsPerProc: maxEventsPerProc,
		rules:            defaultChainRules,
	}
}

func (c *Correlator) Add(event Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	guid := event.ProcessGUID
	if guid == "" {
		return
	}

	events := c.processEvents[guid]
	events = append(events, event)

	if len(events) > c.maxEventsPerProc {
		events = events[len(events)-c.maxEventsPerProc:]
	}

	c.processEvents[guid] = events
}

func (c *Correlator) Evaluate(processGUID string) *CorrelationChain {
	c.mu.RLock()
	events := make([]Event, len(c.processEvents[processGUID]))
	copy(events, c.processEvents[processGUID])
	c.mu.RUnlock()

	if len(events) == 0 {
		return nil
	}

	cutoff := time.Now().Add(-c.window)
	var recent []Event
	for _, e := range events {
		if e.Timestamp.After(cutoff) {
			recent = append(recent, e)
		}
	}

	if len(recent) < 2 {
		return nil
	}

	chain := &CorrelationChain{
		ProcessGUID: processGUID,
		Events:      recent,
	}

	var bestScore float64
	for _, rule := range c.rules {
		if matched, evidence := rule.match(recent); matched {
			chain.ChainDesc = append(chain.ChainDesc, rule.name)
			chain.Evidence = append(chain.Evidence, evidence...)
			if rule.score > bestScore {
				bestScore = rule.score
			}
		}
	}

	if bestScore == 0 {
		return nil
	}

	chain.Score = bestScore
	chain.Verdict = scoreToVerdict(bestScore)
	chain.Actions = c.buildActions(chain)

	return chain
}

func (c *Correlator) EvaluateAll() []*CorrelationChain {
	c.mu.RLock()
	guids := make([]string, 0, len(c.processEvents))
	for guid := range c.processEvents {
		guids = append(guids, guid)
	}
	c.mu.RUnlock()

	var results []*CorrelationChain
	for _, guid := range guids {
		if chain := c.Evaluate(guid); chain != nil {
			results = append(results, chain)
		}
	}
	return results
}

func (c *Correlator) Prune() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-c.window * 2)
	for guid, events := range c.processEvents {
		var kept []Event
		for _, e := range events {
			if e.Timestamp.After(cutoff) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(c.processEvents, guid)
		} else {
			c.processEvents[guid] = kept
		}
	}
}

func (c *Correlator) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.processEvents)
}

func (c *Correlator) buildActions(chain *CorrelationChain) []Action {
	var actions []Action
	for _, e := range chain.Events {
		if e.ProcessID == 0 {
			continue
		}
		actions = append(actions, Action{
			ID:         generateEventID(),
			Timestamp:  time.Now(),
			HostName:   e.HostName,
			ActionType: ActionKillPID,
			Target:     fmt.Sprintf("%d", e.ProcessID),
			Reason:     fmt.Sprintf("Correlated chain [%s] (score %.2f): %s", strings.Join(chain.ChainDesc, ", "), chain.Score, strings.Join(chain.Evidence, "; ")),
		})
		if (e.EventType == EventTypeNetwork || e.EventType == "connect") && e.RemoteAddr != "" {
			actions = append(actions, Action{
				ID:         generateEventID(),
				Timestamp:  time.Now(),
				HostName:   e.HostName,
				ActionType: ActionBlockIP,
				Target:     e.RemoteAddr,
				Reason:     fmt.Sprintf("Correlated chain [%s] (score %.2f): connection to %s", strings.Join(chain.ChainDesc, ", "), chain.Score, e.RemoteAddr),
			})
		}
	}
	return actions
}

func scoreToVerdict(score float64) string {
	switch {
	case score >= 0.8:
		return "malicious"
	case score >= 0.6:
		return "suspicious"
	default:
		return "benign"
	}
}

func isSensitiveWrite(e Event) bool {
	if !strings.Contains(e.FileFlags, "O_WRONLY") &&
		!strings.Contains(e.FileFlags, "O_RDWR") &&
		!strings.Contains(e.FileFlags, "O_CREAT") {
		return false
	}
	for _, re := range sensitiveFileRegexps {
		if re.MatchString(e.FilePath) {
			return true
		}
	}
	return false
}

func extractDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return path
}

func containsAnyTempPath(s string) bool {
	return strings.Contains(s, "/tmp/") ||
		strings.Contains(s, "/var/tmp/") ||
		strings.Contains(s, "/dev/shm/")
}
