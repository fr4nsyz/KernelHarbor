package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"KernelHarbor/cmd/analysis/internal/incidents"
	"KernelHarbor/cmd/analysis/internal/llm"

	"github.com/gin-gonic/gin"
)

type queryEventLike struct {
	event Event
}

var apiKey string

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if apiKey == "" {
			c.Next()
			return
		}
		if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/ready" {
			c.Next()
			return
		}
		if c.GetHeader("X-API-Key") == apiKey {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid API key"})
	}
}

func (e queryEventLike) GetEventType() string   { return e.event.EventType }
func (e queryEventLike) GetCommandLine() string { return e.event.CommandLine }
func (e queryEventLike) GetImagePath() string   { return e.event.ImagePath }
func (e queryEventLike) GetRemoteAddr() string  { return e.event.RemoteAddr }
func (e queryEventLike) GetRemotePort() uint16  { return e.event.RemotePort }
func (e queryEventLike) GetProcessID() uint32   { return e.event.ProcessID }
func (e queryEventLike) GetParentGUID() string  { return e.event.ParentGUID }
func (e queryEventLike) GetHostName() string    { return e.event.HostName }
func (e queryEventLike) GetFilePath() string    { return e.event.FilePath }

func registerHealthRoutes(r *gin.Engine) {
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":   "ok",
			"events":   "ready",
			"analyzer": "ready",
		})
	})

	r.GET("/ready", func(c *gin.Context) {
		llmReady := llmBackend != nil && llmBackend.Name() != "none"
		c.JSON(http.StatusOK, gin.H{
			"elasticsearch": esClientInstance != nil,
			"llm":           llmReady,
		})
	})
}

func registerIngestRoutes(r *gin.Engine, ctx context.Context) {
	r.POST("/ingest", func(c *gin.Context) {
		raw, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
			return
		}

		var events []Event
		var single Event
		if err := json.Unmarshal(raw, &single); err == nil && single.EventType != "" {
			events = []Event{single}
		} else if err := json.Unmarshal(raw, &events); err != nil || len(events) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "expected a single event object or array of events"})
			return
		}

		for i := range events {
			if events[i].Timestamp.IsZero() {
				events[i].Timestamp = time.Now()
			}
			if events[i].EventID == "" {
				events[i].EventID = generateEventID()
			}

			query := events[i].CommandLine
			if query == "" {
				query = events[i].FilePath
			}
			if query == "" {
				query = events[i].RemoteAddr
			}

			if autoAnalyzeByDefault && query != "" {
				if hasSuspiciousPattern(query) {
					actionStore.Add(events[i].HostName, Action{
						ID:         generateEventID(),
						Timestamp:  time.Now(),
						HostName:   events[i].HostName,
						ActionType: ActionKillPID,
						Target:     strconv.Itoa(int(events[i].ProcessID)),
						Reason:     fmt.Sprintf("Heuristic match: %s", query),
					})
					addHeuristicAlert(events[i])
				}
			}

			log.Printf("Received event: %s [%s] PID=%d CMD=%s",
				events[i].EventType, events[i].EventID, events[i].ProcessID, events[i].CommandLine)

			if processor != nil {
				processor.Submit(events[i])
			}
		}

		if esClientInstance != nil {
			if err := esClientInstance.BulkIndex(ctx, events); err != nil {
				log.Printf("Failed to index events: %v", err)
			}
		}

		hostName := ""
		if len(events) > 0 {
			hostName = events[0].HostName
		}
		actions := actionStore.Fetch(hostName)
		if actions == nil {
			actions = []Action{}
		}
		c.JSON(http.StatusAccepted, gin.H{
			"accepted": len(events),
			"actions":  actions,
		})
	})

	r.POST("/ingest/batch", func(c *gin.Context) {
		raw, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
			return
		}

		var batch EventBatch
		var single Event
		if err := json.Unmarshal(raw, &single); err == nil && single.EventType != "" {
			batch.Events = []Event{single}
		} else if err := json.Unmarshal(raw, &batch); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if len(batch.Events) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no events in batch"})
			return
		}

		if batch.ReceivedAt.IsZero() {
			batch.ReceivedAt = time.Now()
		}

		for i := range batch.Events {
			if batch.Events[i].Timestamp.IsZero() {
				batch.Events[i].Timestamp = batch.ReceivedAt
			}
			if batch.Events[i].EventID == "" {
				batch.Events[i].EventID = generateEventID()
			}
			if batch.Events[i].HostName == "" {
				batch.Events[i].HostName = batch.HostName
			}

			query := batch.Events[i].CommandLine
			if query == "" {
				query = batch.Events[i].FilePath
			}
			if query == "" {
				query = batch.Events[i].RemoteAddr
			}

			if autoAnalyzeByDefault && query != "" && hasSuspiciousPattern(query) {
				actionStore.Add(batch.Events[i].HostName, Action{
					ID:         generateEventID(),
					Timestamp:  time.Now(),
					HostName:   batch.Events[i].HostName,
					ActionType: ActionKillPID,
					Target:     strconv.Itoa(int(batch.Events[i].ProcessID)),
					Reason:     fmt.Sprintf("Heuristic match: %s", query),
				})
				addHeuristicAlert(batch.Events[i])
			}

			if processor != nil {
				processor.Submit(batch.Events[i])
			}
		}

		if esClientInstance != nil {
			if err := esClientInstance.BulkIndex(ctx, batch.Events); err != nil {
				log.Printf("Failed to index batch: %v", err)
			}
		}

		actions := actionStore.Fetch(batch.HostName)
		if actions == nil {
			actions = []Action{}
		}
		c.JSON(http.StatusAccepted, gin.H{
			"accepted": len(batch.Events),
			"actions":  actions,
		})
	})

	r.GET("/actions/:hostname", func(c *gin.Context) {
		hostname := c.Param("hostname")
		actions := actionStore.Fetch(hostname)
		if actions == nil {
			actions = []Action{}
		}
		c.JSON(http.StatusOK, gin.H{"actions": actions})
	})
}

func registerAnalysisRoutes(r *gin.Engine) {
	r.POST("/analyze", func(c *gin.Context) {
		var req struct {
			HostName string `json:"host.name" binding:"required"`
			Query    string `json:"query" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if llmBackend == nil || llmBackend.Name() == "none" {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LLM backend not configured"})
			return
		}

		evt := Event{
			HostName:    req.HostName,
			EventType:   "analyze",
			CommandLine: req.Query,
		}

		analysisReq := llm.AnalysisRequest{
			Events:   []llm.EventLike{queryEventLike{evt}},
			HostName: req.HostName,
		}

		result, err := llmBackend.Analyze(analysisReq)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "analysis failed: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"verdict":    result.Verdict,
			"confidence": result.Confidence,
			"evidence":   result.Evidence,
			"summary":    result.Summary,
			"model":      result.ModelUsed,
		})
	})
}

func registerDashboardRoutes(r *gin.Engine, alertStore *AlertStore, incidentStore *incidents.Store) {
	r.GET("/api/alerts", func(c *gin.Context) {
		since := c.DefaultQuery("since", "24h")
		minVerdict := c.DefaultQuery("min_verdict", "suspicious")
		limitStr := c.DefaultQuery("limit", "100")

		duration, err := time.ParseDuration(since)
		if err != nil {
			duration = 24 * time.Hour
		}
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			limit = 100
		}

		alerts := alertStore.List(time.Now().Add(-duration), minVerdict, limit)
		if alerts == nil {
			alerts = []Alert{}
		}
		c.JSON(http.StatusOK, gin.H{"alerts": alerts})
	})

	r.GET("/api/alerts/stats", func(c *gin.Context) {
		stats := alertStore.Stats()
		c.JSON(http.StatusOK, stats)
	})

	r.POST("/api/alerts/:id/feedback", func(c *gin.Context) {
		id := c.Param("id")
		var req struct {
			Feedback string `json:"feedback" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if req.Feedback != "confirmed" && req.Feedback != "false_positive" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "feedback must be 'confirmed' or 'false_positive'"})
			return
		}

		if alertStore.SetFeedback(id, req.Feedback) {
			if incidentStore != nil {
				incidentStore.Update(id, func(inc *incidents.Incident) {
					inc.IsVerified = req.Feedback == "confirmed"
				})
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		}
	})

	r.GET("/api/incidents", func(c *gin.Context) {
		if incidentStore == nil {
			c.JSON(http.StatusOK, gin.H{"incidents": []incidents.IncRef{}})
			return
		}
		refs := incidentStore.List()
		if refs == nil {
			refs = []incidents.IncRef{}
		}
		c.JSON(http.StatusOK, gin.H{"incidents": refs})
	})
}
