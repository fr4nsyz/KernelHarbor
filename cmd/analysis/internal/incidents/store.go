package incidents

import (
	"math"
	"sort"
	"sync"
	"time"
)

type EventLike interface {
	GetEventType() string
	GetCommandLine() string
	GetImagePath() string
}

type Incident struct {
	ID         string
	CreatedAt  time.Time
	Events     []EventLike
	Embedding  []float32
	Verdict    string
	IsVerified bool
	Summary    string
}

type IncRef struct {
	ID       string
	Verdict  string
	Verified bool
	Summary  string
	Score    float64
}

type Store struct {
	mu        sync.RWMutex
	incidents []*Incident
}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) Add(incident *Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incidents = append(s.incidents, incident)
}

func (s *Store) SearchSimilar(embedding []float32, limit int) []IncRef {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type scored struct {
		inc   *Incident
		score float64
	}

	var results []scored
	for _, inc := range s.incidents {
		if len(inc.Embedding) == 0 {
			continue
		}
		sim := cosineSimilarity(embedding, inc.Embedding)
		if sim > 0.6 {
			results = append(results, scored{inc, sim})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	if len(results) > limit {
		results = results[:limit]
	}

	refs := make([]IncRef, len(results))
	for i, r := range results {
		refs[i] = IncRef{
			ID:       r.inc.ID,
			Verdict:  r.inc.Verdict,
			Verified: r.inc.IsVerified,
			Summary:  r.inc.Summary,
			Score:    r.score,
		}
	}
	return refs
}

func (s *Store) List() []IncRef {
	s.mu.RLock()
	defer s.mu.RUnlock()

	refs := make([]IncRef, len(s.incidents))
	for i, inc := range s.incidents {
		refs[i] = IncRef{
			ID:       inc.ID,
			Verdict:  inc.Verdict,
			Verified: inc.IsVerified,
			Summary:  inc.Summary,
		}
	}
	return refs
}

func (s *Store) Update(id string, fn func(*Incident)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inc := range s.incidents {
		if inc.ID == id {
			fn(inc)
			return
		}
	}
}

func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}

	denom := math.Sqrt(normA) * math.Sqrt(normB)
	if denom == 0 {
		return 0
	}

	return dot / denom
}
