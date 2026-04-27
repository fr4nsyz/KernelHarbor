package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

type Config struct {
	Server struct {
		Addr string `yaml:"addr" json:"addr"`
	} `yaml:"server" json:"server"`
	Protocol      string `yaml:"protocol" json:"protocol"`
	Elasticsearch struct {
		Addresses []string `yaml:"addresses" json:"addresses"`
		Username  string   `yaml:"username" json:"username"`
		Password  string   `yaml:"password" json:"password"`
		Index     string   `yaml:"index" json:"index"`
	} `yaml:"elasticsearch" json:"elasticsearch"`
	Ollama struct {
		Address    string `yaml:"address" json:"address"`
		Model      string `yaml:"model" json:"model"`
		EmbedModel string `yaml:"embed_model" json:"embed_model"`
		EmbedDim   int    `yaml:"embed_dim" json:"embed_dim"`
	} `yaml:"ollama" json:"ollama"`
	Processor struct {
		Workers      int           `yaml:"workers" json:"workers"`
		BatchSize    int           `yaml:"batch_size" json:"batch_size"`
		BatchTimeout time.Duration `yaml:"batch_timeout" json:"batch_timeout"`
	} `yaml:"processor" json:"processor"`
}

func getDefaultConfig() Config {
	return Config{
		Server: struct {
			Addr string `yaml:"addr" json:"addr"`
		}{Addr: ":8080"},
		Protocol: "both",
		Elasticsearch: struct {
			Addresses []string `yaml:"addresses" json:"addresses"`
			Username  string   `yaml:"username" json:"username"`
			Password  string   `yaml:"password" json:"password"`
			Index     string   `yaml:"index" json:"index"`
		}{
			Addresses: []string{"http://localhost:9200"},
			Index:     EventsIndex,
		},
		Ollama: struct {
			Address    string `yaml:"address" json:"address"`
			Model      string `yaml:"model" json:"model"`
			EmbedModel string `yaml:"embed_model" json:"embed_model"`
			EmbedDim   int    `yaml:"embed_dim" json:"embed_dim"`
		}{
			Address:    "http://localhost:11434",
			Model:      "qwen2.5:7b",
			EmbedModel: "nomic-embed-text",
			EmbedDim:   VectorDim,
		},
		Processor: struct {
			Workers      int           `yaml:"workers" json:"workers"`
			BatchSize    int           `yaml:"batch_size" json:"batch_size"`
			BatchTimeout time.Duration `yaml:"batch_timeout" json:"batch_timeout"`
		}{
			Workers:      3,
			BatchSize:    100,
			BatchTimeout: 30 * time.Second,
		},
	}
}

func main() {
	noAutoAnalyze := flag.Bool("no-auto-analyze", false, "Disable automatic analysis on ingest")
	flag.Parse()
	autoAnalyzeByDefault = !*noAutoAnalyze

	cfg := getDefaultConfig()

	if addr := os.Getenv("ES_ADDRESSES"); addr != "" {
		cfg.Elasticsearch.Addresses = []string{addr}
	}
	if user := os.Getenv("ES_USERNAME"); user != "" {
		cfg.Elasticsearch.Username = user
		cfg.Elasticsearch.Password = os.Getenv("ES_PASSWORD")
	}
	if esIndex := os.Getenv("ES_INDEX"); esIndex != "" {
		cfg.Elasticsearch.Index = esIndex
	}
	if ollamaAddr := os.Getenv("OLLAMA_ADDRESS"); ollamaAddr != "" {
		cfg.Ollama.Address = ollamaAddr
	}
	if ollamaModel := os.Getenv("OLLAMA_MODEL"); ollamaModel != "" {
		cfg.Ollama.Model = ollamaModel
	}
	if protocol := os.Getenv("PROTOCOL"); protocol != "" {
		cfg.Protocol = protocol
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if len(cfg.Elasticsearch.Addresses) > 0 {
		es, err := NewESClient(ESConfig{
			Addresses: cfg.Elasticsearch.Addresses,
			Username:  cfg.Elasticsearch.Username,
			Password:  cfg.Elasticsearch.Password,
			Index:     cfg.Elasticsearch.Index,
		})
		if err != nil {
			log.Printf("Warning: Failed to connect to Elasticsearch: %v", err)
		} else {
			log.Printf("Connected to Elasticsearch at %v", cfg.Elasticsearch.Addresses)
			_ = es
		}
	}

	ollamaClient = NewOllamaClient(OllamaConfig{
		Address:    cfg.Ollama.Address,
		Model:      cfg.Ollama.Model,
		EmbedModel: cfg.Ollama.EmbedModel,
		EmbedDim:   cfg.Ollama.EmbedDim,
	})
	log.Printf("Ollama client configured: %s %s", cfg.Ollama.Address, cfg.Ollama.Model)

	if apiKey := os.Getenv("ABUSEIPDB_API_KEY"); apiKey != "" {
		blacklistClient = NewBlacklistClient(BlacklistConfig{
			AbuseIPDBAPIKey: apiKey,
			CacheExpiry:     1 * time.Hour,
		})
		log.Printf("Blacklist client configured with AbuseIPDB")
	}

	processor = NewBatchProcessor(BatchProcessorConfig{
		Workers:      cfg.Processor.Workers,
		BatchSize:    cfg.Processor.BatchSize,
		BatchTimeout: cfg.Processor.BatchTimeout,
	})
	processor.Start()

	router := gin.Default()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":   "ok",
			"events":   "ready",
			"analyzer": "ready",
		})
	})

	router.GET("/ready", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"elasticsearch": esClientInstance != nil,
			"ollama":        ollamaClient != nil,
		})
	})

	router.POST("/ingest", func(c *gin.Context) {
		var events []Event
		if err := c.ShouldBindJSON(&events); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

			verdict := "benign"
			confidence := float32(0.0)

			if autoAnalyzeByDefault && query != "" {
				if hasSuspiciousPattern(query) {
					verdict = "suspicious"
					confidence = 0.7
				} else {
					confidence = 0.3
				}
			}

			if blacklistClient != nil && autoBlacklistCheck.Enabled {
				blVerdict, blConf, blReason := checkBlacklist(context.Background(), &events[i])
				if blVerdict == "suspicious" && blConf > float64(confidence) {
					verdict = blVerdict
					confidence = float32(blConf)
					if events[i].Metadata == nil {
						events[i].Metadata = make(map[string]any)
					}
					events[i].Metadata["blacklist_verdict"] = blReason
				}
			}

			log.Printf("Received event: %s [%s] PID=%d CMD=%s | VERDICT=%s CONFIDENCE=%.2f",
				events[i].EventType, events[i].EventID, events[i].ProcessID, events[i].CommandLine, verdict, confidence)

			processor.Submit(events[i])
		}

		if esClientInstance != nil {
			if err := esClientInstance.BulkIndex(ctx, events); err != nil {
				log.Printf("Failed to index events: %v", err)
			}
		}

		c.JSON(http.StatusAccepted, gin.H{
			"accepted": len(events),
		})
	})

	router.POST("/ingest/batch", func(c *gin.Context) {
		var batch EventBatch
		if err := c.ShouldBindJSON(&batch); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

			processor.Submit(batch.Events[i])
		}

		if esClientInstance != nil {
			if err := esClientInstance.BulkIndex(ctx, batch.Events); err != nil {
				log.Printf("Failed to index batch: %v", err)
			}
		}

		c.JSON(http.StatusAccepted, gin.H{
			"accepted": len(batch.Events),
		})
	})

	router.POST("/analyze", func(c *gin.Context) {
		var req struct {
			HostName string `json:"host.name" binding:"required"`
			Query    string `json:"query" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if ollamaClient == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ollama not configured"})
			return
		}

		prompt := "Analyze this security event: " + req.Query + "\nIs this malicious? Answer in JSON format: {\"verdict\": \"benign|suspicious|malicious\", \"confidence\": 0.0-1.0, \"summary\": \"brief explanation\"}"
		log.Printf("Prompt: %s", prompt)

		response, err := ollamaClient.Generate(context.Background(), prompt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "generation failed: " + err.Error()})
			return
		}

		verdict, confidence, evidence, summary, _ := parseAnalysisResponse(response)

		c.JSON(http.StatusOK, gin.H{
			"verdict":    verdict,
			"confidence": confidence,
			"evidence":   evidence,
			"summary":    summary,
			"raw":        response,
		})
	})

	srv := &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: router,
	}

	if cfg.Protocol == "http" || cfg.Protocol == "both" {
		go func() {
			log.Printf("Starting HTTP server on %s", cfg.Server.Addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start server: %v", err)
			}
		}()
	}

	grpcAddr := ":9090"
	if g := os.Getenv("GRPC_ADDRESS"); g != "" {
		grpcAddr = g
	}

	var grpcWg sync.WaitGroup
	if cfg.Protocol == "grpc" || cfg.Protocol == "both" {
		grpcWg.Add(1)
		go startGrpcServer(grpcAddr, &grpcWg)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	processor.Stop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if cfg.Protocol == "http" || cfg.Protocol == "both" {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}

	if cfg.Protocol == "grpc" || cfg.Protocol == "both" {
		if grpcServer != nil {
			grpcServer.GracefulStop()
		}
		grpcWg.Wait()
	}

	log.Println("Server stopped")
}

func generateEventID() string {
	return time.Now().Format("20060102150405.000000") + "-" + randomString(8)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}
