package main

import (
	"sync"
	"time"
)

type ProcessInfo struct {
	ProcessGUID    string
	ParentGUID     string
	PID            uint32
	ParentPID      uint32
	ImagePath      string
	CommandLine    string
	HostName       string
	FirstSeen      time.Time
	LastSeen       time.Time
	HeuristicScore float32
}

type ProcessCache struct {
	mu      sync.RWMutex
	cache   map[string]*ProcessInfo
	order   []string
	maxSize int
}

func NewProcessCache(maxSize int) *ProcessCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &ProcessCache{
		cache:   make(map[string]*ProcessInfo, maxSize),
		order:   make([]string, 0, maxSize),
		maxSize: maxSize,
	}
}

func (pc *ProcessCache) Record(event Event) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	now := time.Now()
	guid := event.ProcessGUID
	if guid == "" {
		return
	}

	if existing, ok := pc.cache[guid]; ok {
		existing.LastSeen = now
		if event.CommandLine != "" {
			existing.CommandLine = event.CommandLine
		}
		if event.ImagePath != "" {
			existing.ImagePath = event.ImagePath
		}
		return
	}

	if len(pc.order) >= pc.maxSize {
		pc.evictOldest()
	}

	info := &ProcessInfo{
		ProcessGUID: guid,
		ParentGUID:  event.ParentGUID,
		PID:         event.ProcessID,
		ParentPID:   event.ParentPID,
		ImagePath:   event.ImagePath,
		CommandLine: event.CommandLine,
		HostName:    event.HostName,
		FirstSeen:   now,
		LastSeen:    now,
	}
	pc.cache[guid] = info
	pc.order = append(pc.order, guid)
}

func (pc *ProcessCache) Get(guid string) (*ProcessInfo, bool) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	info, ok := pc.cache[guid]
	return info, ok
}

func (pc *ProcessCache) UpdateScore(guid string, score float32) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if info, ok := pc.cache[guid]; ok {
		if score > info.HeuristicScore {
			info.HeuristicScore = score
		}
	}
}

func (pc *ProcessCache) RecordHeuristicScore(event Event, score float32) {
	pc.Record(event)
	pc.UpdateScore(event.ProcessGUID, score)
}

func (pc *ProcessCache) evictOldest() {
	if len(pc.order) == 0 {
		return
	}
	oldest := pc.order[0]
	pc.order = pc.order[1:]
	delete(pc.cache, oldest)
}

func (pc *ProcessCache) Size() int {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return len(pc.cache)
}
