package main

import (
	"sync"
	"testing"
	"time"
)

func TestProcessCacheRecordAndGet(t *testing.T) {
	cache := NewProcessCache(100)

	event := Event{
		ProcessGUID: "host-1000-1234",
		ParentGUID:  "host-1-0001",
		ProcessID:   1000,
		ParentPID:   1,
		ImagePath:   "/usr/bin/bash",
		CommandLine: "bash -c 'ls'",
		HostName:    "testhost",
		Timestamp:   time.Now(),
	}

	cache.Record(event)

	info, ok := cache.Get("host-1000-1234")
	if !ok {
		t.Fatal("expected to find process in cache")
	}
	if info.ProcessGUID != "host-1000-1234" {
		t.Errorf("ProcessGUID = %q, want host-1000-1234", info.ProcessGUID)
	}
	if info.ParentGUID != "host-1-0001" {
		t.Errorf("ParentGUID = %q, want host-1-0001", info.ParentGUID)
	}
	if info.PID != 1000 {
		t.Errorf("PID = %d, want 1000", info.PID)
	}
	if info.ImagePath != "/usr/bin/bash" {
		t.Errorf("ImagePath = %q, want /usr/bin/bash", info.ImagePath)
	}
}

func TestProcessCacheUpdateExisting(t *testing.T) {
	cache := NewProcessCache(100)

	cache.Record(Event{
		ProcessGUID: "host-1000-1234",
		ProcessID:   1000,
		ImagePath:   "/usr/bin/bash",
		HostName:    "test",
		Timestamp:   time.Now(),
	})

	cache.Record(Event{
		ProcessGUID: "host-1000-1234",
		ProcessID:   1000,
		ImagePath:   "/usr/bin/bash",
		CommandLine: "bash -c 'updated command'",
		HostName:    "test",
		Timestamp:   time.Now().Add(time.Millisecond),
	})

	info, ok := cache.Get("host-1000-1234")
	if !ok {
		t.Fatal("expected to find process")
	}
	if info.CommandLine != "bash -c 'updated command'" {
		t.Errorf("CommandLine = %q, want updated command", info.CommandLine)
	}
	if cache.Size() != 1 {
		t.Errorf("Size = %d, want 1 (should not duplicate)", cache.Size())
	}
}

func TestProcessCacheEviction(t *testing.T) {
	cache := NewProcessCache(3)

	for i := 0; i < 5; i++ {
		cache.Record(Event{
			ProcessGUID: "host-" + string(rune('A'+i)) + "-0001",
			ProcessID:   uint32(i),
			HostName:    "test",
			Timestamp:   time.Now(),
		})
	}

	if cache.Size() != 3 {
		t.Errorf("Size = %d, want 3 (eviction)", cache.Size())
	}

	_, ok := cache.Get("host-A-0001")
	if ok {
		t.Error("expected oldest entry to be evicted")
	}

	_, ok = cache.Get("host-E-0001")
	if !ok {
		t.Error("expected newest entry to exist")
	}
}

func TestProcessCacheUpdateScore(t *testing.T) {
	cache := NewProcessCache(100)

	cache.Record(Event{
		ProcessGUID: "host-1000-1234",
		ProcessID:   1000,
		HostName:    "test",
		Timestamp:   time.Now(),
	})

	cache.UpdateScore("host-1000-1234", 0.5)
	info, _ := cache.Get("host-1000-1234")
	if info.HeuristicScore != 0.5 {
		t.Errorf("HeuristicScore = %.2f, want 0.5", info.HeuristicScore)
	}

	cache.UpdateScore("host-1000-1234", 0.8)
	info, _ = cache.Get("host-1000-1234")
	if info.HeuristicScore != 0.8 {
		t.Errorf("HeuristicScore = %.2f, want 0.8 (should increase)", info.HeuristicScore)
	}

	cache.UpdateScore("host-1000-1234", 0.3)
	info, _ = cache.Get("host-1000-1234")
	if info.HeuristicScore != 0.8 {
		t.Errorf("HeuristicScore = %.2f, want 0.8 (should not decrease)", info.HeuristicScore)
	}
}

func TestProcessCacheRecordHeuristicScore(t *testing.T) {
	cache := NewProcessCache(100)

	event := Event{
		ProcessGUID: "host-1000-1234",
		ProcessID:   1000,
		HostName:    "test",
		Timestamp:   time.Now(),
	}

	cache.RecordHeuristicScore(event, 0.7)

	info, ok := cache.Get("host-1000-1234")
	if !ok {
		t.Fatal("expected to find process")
	}
	if info.HeuristicScore != 0.7 {
		t.Errorf("HeuristicScore = %.2f, want 0.7", info.HeuristicScore)
	}
}

func TestProcessCacheEmptyGUID(t *testing.T) {
	cache := NewProcessCache(100)

	cache.Record(Event{
		ProcessGUID: "",
		ProcessID:   1000,
		HostName:    "test",
		Timestamp:   time.Now(),
	})

	if cache.Size() != 0 {
		t.Errorf("Size = %d, want 0 (empty GUID should not be cached)", cache.Size())
	}
}

func TestProcessCacheConcurrentAccess(t *testing.T) {
	cache := NewProcessCache(1000)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			guid := "host-" + string(rune('A'+id%26)) + "-0001"
			cache.Record(Event{
				ProcessGUID: guid,
				ProcessID:   uint32(id),
				HostName:    "test",
				Timestamp:   time.Now(),
			})
			cache.Get(guid)
			cache.UpdateScore(guid, float32(id%10)/10.0)
		}(i)
	}
	wg.Wait()

	if cache.Size() == 0 {
		t.Error("expected some entries in cache after concurrent access")
	}
}
