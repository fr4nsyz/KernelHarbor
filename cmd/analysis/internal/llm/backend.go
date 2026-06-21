package llm

import (
	"time"
)

type EventLike interface {
	GetEventType() string
	GetCommandLine() string
	GetImagePath() string
	GetRemoteAddr() string
	GetRemotePort() uint16
	GetProcessID() uint32
	GetParentGUID() string
	GetHostName() string
}

type IncidentRef struct {
	ID       string
	Verdict  string
	Verified bool
	Summary  string
}

type AnalysisRequest struct {
	Events           []EventLike
	ProcessChains    map[string][]EventLike
	SimilarIncidents []IncidentRef
	Interestingness  float64
	HostName         string
}

type AnalysisResult struct {
	Verdict     string // "benign", "suspicious", "malicious"
	Confidence  float64
	Evidence    []string
	Summary     string
	IncidentRef string
	ModelUsed   string
	Timestamp   time.Time
}

type Backend interface {
	Analyze(req AnalysisRequest) (*AnalysisResult, error)
	Name() string
}
