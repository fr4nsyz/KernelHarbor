package main

import (
	"context"
	"crypto/rand"
	"flag"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"KernelHarbor/cmd/analysis/internal/incidents"
	"KernelHarbor/cmd/analysis/internal/interestingness"
	"KernelHarbor/cmd/analysis/internal/llm"

	"github.com/gin-gonic/gin"
)

type Config struct {
	HTTPAddr string `json:"http_addr"`
	GRPCAddr string `json:"grpc_addr"`
	Protocol string `json:"protocol"`

	Elasticsearch struct {
		Addresses []string `json:"addresses"`
		Username  string   `json:"username"`
		Password  string   `json:"password"`
		Index     string   `json:"index"`
	} `json:"elasticsearch"`

	LLM struct {
		Backend   string  `json:"backend"`   // "none", "ollama", "openai", "anthropic"
		Threshold float64 `json:"threshold"` // 0.0-1.0, default 0.6

		Ollama struct {
			Address    string `json:"address"`
			Model      string `json:"model"`
			EmbedModel string `json:"embed_model"`
			EmbedDim   int    `json:"embed_dim"`
		} `json:"ollama"`

		OpenAI struct {
			APIKey string `json:"api_key"`
			Model  string `json:"model"`
		} `json:"openai"`

		Anthropic struct {
			APIKey string `json:"api_key"`
			Model  string `json:"model"`
		} `json:"anthropic"`
	} `json:"llm"`

	Processor struct {
		Workers      int           `json:"workers"`
		BatchSize    int           `json:"batch_size"`
		BatchTimeout time.Duration `json:"batch_timeout"`
	} `json:"processor"`
}

func getDefaultConfig() Config {
	return Config{
		HTTPAddr: ":8080",
		GRPCAddr: ":9090",
		Protocol: "both",
		Elasticsearch: struct {
			Addresses []string `json:"addresses"`
			Username  string   `json:"username"`
			Password  string   `json:"password"`
			Index     string   `json:"index"`
		}{
			Addresses: []string{"http://localhost:9200"},
			Index:     EventsIndex,
		},
		LLM: struct {
			Backend   string  `json:"backend"`
			Threshold float64 `json:"threshold"`
			Ollama    struct {
				Address    string `json:"address"`
				Model      string `json:"model"`
				EmbedModel string `json:"embed_model"`
				EmbedDim   int    `json:"embed_dim"`
			} `json:"ollama"`
			OpenAI struct {
				APIKey string `json:"api_key"`
				Model  string `json:"model"`
			} `json:"openai"`
			Anthropic struct {
				APIKey string `json:"api_key"`
				Model  string `json:"model"`
			} `json:"anthropic"`
		}{
			Backend:   "none",
			Threshold: 0.6,
			Ollama: struct {
				Address    string `json:"address"`
				Model      string `json:"model"`
				EmbedModel string `json:"embed_model"`
				EmbedDim   int    `json:"embed_dim"`
			}{
				Address:    "http://localhost:11434",
				Model:      "qwen2.5:7b",
				EmbedModel: "nomic-embed-text",
				EmbedDim:   VectorDim,
			},
		},
		Processor: struct {
			Workers      int           `json:"workers"`
			BatchSize    int           `json:"batch_size"`
			BatchTimeout time.Duration `json:"batch_timeout"`
		}{
			Workers:      3,
			BatchSize:    100,
			BatchTimeout: 5 * time.Second,
		},
	}
}

func main() {
	noAutoAnalyze := flag.Bool("no-auto-analyze", false, "Disable automatic analysis on ingest")
	flag.Parse()
	autoAnalyzeByDefault = !*noAutoAnalyze

	cfg := getDefaultConfig()

	// Environment overrides for Elasticsearch
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

	// Environment overrides for LLM
	if backend := os.Getenv("LLM_BACKEND"); backend != "" {
		cfg.LLM.Backend = backend
	}
	if threshold := os.Getenv("LLM_THRESHOLD"); threshold != "" {
		if v, err := strconv.ParseFloat(threshold, 64); err == nil {
			cfg.LLM.Threshold = v
		}
	}
	if ollamaAddr := os.Getenv("OLLAMA_ADDRESS"); ollamaAddr != "" {
		cfg.LLM.Ollama.Address = ollamaAddr
	}
	if ollamaModel := os.Getenv("OLLAMA_MODEL"); ollamaModel != "" {
		cfg.LLM.Ollama.Model = ollamaModel
	}
	if openAIKey := os.Getenv("OPENAI_API_KEY"); openAIKey != "" {
		cfg.LLM.OpenAI.APIKey = openAIKey
	}
	if openAIModel := os.Getenv("OPENAI_MODEL"); openAIModel != "" {
		cfg.LLM.OpenAI.Model = openAIModel
	}
	if anthropicKey := os.Getenv("ANTHROPIC_API_KEY"); anthropicKey != "" {
		cfg.LLM.Anthropic.APIKey = anthropicKey
	}
	if anthropicModel := os.Getenv("ANTHROPIC_MODEL"); anthropicModel != "" {
		cfg.LLM.Anthropic.Model = anthropicModel
	}

	// Protocol override
	if protocol := os.Getenv("PROTOCOL"); protocol != "" {
		cfg.Protocol = protocol
	}

	// gRPC address override
	if g := os.Getenv("GRPC_ADDRESS"); g != "" {
		cfg.GRPCAddr = g
	}

	// HTTP address override
	if h := os.Getenv("HTTP_ADDRESS"); h != "" {
		cfg.HTTPAddr = h
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize state
	actionStore = NewActionStore()
	alertStore = NewAlertStore()
	interestingnessScorer := interestingness.New()
	incidentStore = incidents.NewStore()

	// Connect to Elasticsearch (optional)
	if len(cfg.Elasticsearch.Addresses) > 0 {
		client, err := NewESClient(ESConfig{
			Addresses: cfg.Elasticsearch.Addresses,
			Username:  cfg.Elasticsearch.Username,
			Password:  cfg.Elasticsearch.Password,
			Index:     cfg.Elasticsearch.Index,
		})
		if err != nil {
			log.Printf("Warning: Elasticsearch unavailable: %v (continuing without ES)", err)
		} else {
			esClientInstance = client
			if err := esClientInstance.ensureAlertsIndex(ctx); err != nil {
				log.Printf("Warning: couldn't create alerts index: %v", err)
			} else {
				alerts, err := esClientInstance.LoadAlerts(ctx, time.Now().Add(-72*time.Hour))
				if err != nil {
					log.Printf("Warning: couldn't load alerts from ES: %v", err)
				} else {
					for i := range alerts {
						alertStore.Add(alerts[i])
					}
					log.Printf("Loaded %d alerts from Elasticsearch", len(alerts))
				}
			}
			log.Printf("Connected to Elasticsearch at %v", cfg.Elasticsearch.Addresses)
		}
	}

	// API key for HTTP auth
	apiKey = os.Getenv("KH_API_KEY")
	if apiKey != "" {
		log.Printf("API key authentication enabled")
	} else {
		log.Printf("Warning: KH_API_KEY not set — HTTP API is unprotected")
	}

	// Initialize LLM backend
	var llmBackend llm.Backend
	switch cfg.LLM.Backend {
	case "ollama":
		if cfg.LLM.Ollama.Address == "" {
			log.Fatal("LLM_BACKEND=ollama but OLLAMA_ADDRESS is not set")
		}
		llmBackend = llm.NewOllama(llm.OllamaConfig{
			Address:    cfg.LLM.Ollama.Address,
			Model:      cfg.LLM.Ollama.Model,
			EmbedModel: cfg.LLM.Ollama.EmbedModel,
			EmbedDim:   cfg.LLM.Ollama.EmbedDim,
		})
		log.Printf("LLM backend: ollama (%s)", cfg.LLM.Ollama.Model)
	case "openai":
		if cfg.LLM.OpenAI.APIKey == "" {
			log.Fatal("LLM_BACKEND=openai but OPENAI_API_KEY is not set")
		}
		llmBackend = llm.NewOpenAI(llm.OpenAIConfig{
			APIKey: cfg.LLM.OpenAI.APIKey,
			Model:  cfg.LLM.OpenAI.Model,
		})
		log.Printf("LLM backend: openai (%s)", cfg.LLM.OpenAI.Model)
	case "anthropic":
		if cfg.LLM.Anthropic.APIKey == "" {
			log.Fatal("LLM_BACKEND=anthropic but ANTHROPIC_API_KEY is not set")
		}
		llmBackend = llm.NewAnthropic(llm.AnthropicConfig{
			APIKey: cfg.LLM.Anthropic.APIKey,
			Model:  cfg.LLM.Anthropic.Model,
		})
		log.Printf("LLM backend: anthropic (%s)", cfg.LLM.Anthropic.Model)
	default:
		llmBackend = llm.NewNull()
		log.Printf("LLM backend: none (heuristic-only mode)")
	}

	log.Printf("LLM threshold: %.2f (batches scoring below this skip LLM analysis)", cfg.LLM.Threshold)

	// Initialize batch processor
	processor = NewBatchProcessor(BatchProcessorConfig{
		Workers:      cfg.Processor.Workers,
		BatchSize:    cfg.Processor.BatchSize,
		BatchTimeout: cfg.Processor.BatchTimeout,
		LLMThreshold: cfg.LLM.Threshold,
	})
	processor.SetInterestingness(interestingnessScorer)
	processor.SetLLMBackend(llmBackend)
	processor.SetIncidentStore(incidentStore)
	processor.SetAlertStore(alertStore)
	if o, ok := llmBackend.(*llm.OllamaBackend); ok {
		processor.SetEmbedder(o)
	}
	processor.Start()

	// Initialize HTTP routes
	router := gin.Default()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(authMiddleware())

	// Register routes
	registerHealthRoutes(router)
	registerIngestRoutes(router, ctx)
	registerAnalysisRoutes(router)
	registerDashboardRoutes(router, alertStore, incidentStore)

	// Start HTTP server
	srv := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: router,
	}

	if cfg.Protocol == "http" || cfg.Protocol == "both" {
		go func() {
			log.Printf("HTTP server starting on %s", cfg.HTTPAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server error: %v", err)
			}
		}()
	}

	// Start gRPC server
	var grpcWg sync.WaitGroup
	if cfg.Protocol == "grpc" || cfg.Protocol == "both" {
		grpcWg.Add(1)
		go startGrpcServer(cfg.GRPCAddr, &grpcWg)
	}

	// Wait for shutdown
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
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[idx.Int64()]
	}
	return string(b)
}
