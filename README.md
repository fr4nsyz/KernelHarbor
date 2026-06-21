# KernelHarbor

Linux kernel security monitoring with eBPF, heuristic detection, and optional LLM-powered analysis.

**Three-tier architecture:** Heuristic (Tier 1) → LLM analysis (Tier 2) → Periodic summaries (Tier 3)

**Credits:** [Kien Do](https://github.com/kienmarkdo), [Francois Coleongco](https://github.com/fr4nsyz), [John Tyler](https://github.com/john00003), [Mehar Klair](https://github.com/meharklair)

## Architecture

### Three-Tier Detection Pipeline

```mermaid
graph TB
    subgraph "Agent (eBPF)"
        A1[execve hooks] --> RB[Ring Buffer]
        A2[open hooks] --> RB
        A3[openat hooks] --> RB
        A4[connect hooks] --> RB
        RB --> GP[Go Userspace]
    end

    subgraph "Tier 1 — Heuristic (real-time)"
        GP -->|gRPC Ingest| H1[Regex Pattern Matcher]
        H1 -->|match| H2[Action: KILL_PID / BLOCK_IP]
        H2 -->|same RPC response| GP
        H1 -->|no match| H3[Submit to Batch Processor]
    end

    subgraph "Tier 2 — LLM (30s-5m delay)"
        H3 -->|batch| IS[Interestingness Scorer]
        IS -->|score < threshold| D1[Skip — no LLM call]
        IS -->|score >= threshold| EM[Embeddings]
        EM --> VS[Vector Search: similar incidents]
        VS --> LLM[LLM Backend]
        LLM -->|alerts only, no actions| AL[Alert Store]
        AL --> FB[User Feedback]
        FB -->|confirmed| RAG[Incident Store for future RAG]
    end

    subgraph "Tier 3 — Periodic Summary"
        TS[Timer Trigger] --> SUM[Summarize recent alerts]
        SUM -->|dashboard| UI
    end
```

### Response Flow

```mermaid
graph LR
    subgraph "Heuristic (Tier 1)"
        HE[Regex Match] -->|immediate| KA[KILL_PID]
        HE -->|immediate| BI[BLOCK_IP]
    end

    subgraph "LLM (Tier 2)"
        LA[LLM Verdict] -->|alert only| AS[Alert Store]
        AS -->|confirmed| IS2[Incident Store]
        AS -->|false positive| IS2[Incident Store]
    end

    subgraph "Agent"
        AG[Agent] -->|Ingest| HE
        AG -->|FetchActions| KA
        AG -->|FetchActions| BI
    end
```

**Key design decision:** The LLM never generates automatic actions. Only the heuristic engine (regex patterns) can produce `KILL_PID` and `BLOCK_IP`. The LLM produces alerts for human review, plus labeled incidents that improve future RAG.

| Tier | Trigger | Latency | Actions Produced |
|------|---------|---------|-----------------|
| 1 — Heuristic | Regex match | Same RPC response | `KILL_PID`, `BLOCK_IP` |
| 2 — LLM | Interestingness >= threshold | 30s-5m | Alerts only |
| 3 — Periodic Summary | Timer (configurable) | Hours | Dashboard summaries |

### Event Flow

```mermaid
sequenceDiagram
    participant K as Kernel eBPF
    participant A as Agent (Go)
    participant S as Analysis Server
    participant ES as Elasticsearch
    participant LLM as LLM Backend

    K->>A: Ring buffer event
    A->>S: gRPC Ingest
    S->>S: Regex heuristic check
    S-->>A: Return actions if matched
    S->>ES: Index event
    S->>S: Batch accumulator
    S->>S: Interestingness score
    alt score >= threshold
        S->>LLM: Analyze batch
        LLM-->>S: Verdict + evidence
        S->>S: Store alert
    end
```

## Quick Start

### Prerequisites

```bash
# eBPF toolchain (Debian/Ubuntu)
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r)

# eBPF toolchain (Fedora/RHEL)
sudo dnf install clang llvm libbpf-devel kernel-headers

# Optional: Elasticsearch for event persistence
docker run -d --name elasticsearch -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.17.4

# Optional: Ollama for local LLM
ollama serve
ollama pull nomic-embed-text
ollama pull qwen2.5:7b
```

### Build

```bash
make            # Build everything
make agent      # Build agent only
make analysis   # Build analysis only
make clean      # Remove binaries + generated files
```

### Run

```bash
# Terminal 1: Analysis service (heuristic-only by default, zero external deps)
cd cmd/analysis && ./analysis

# Terminal 2: Agent (requires sudo)
sudo GRPC_ADDRESS=localhost:9090 ./cmd/agent/agent
```

### Run with LLM (Optional)

```bash
# Start analysis with Ollama backend
LLM_BACKEND=ollama cd cmd/analysis && ./analysis

# Or with OpenAI
LLM_BACKEND=openai OPENAI_API_KEY=sk-... cd cmd/analysis && ./analysis
```

## Components

| Component | Directory | Description |
|-----------|-----------|-------------|
| Agent | `cmd/agent/` | Unified eBPF tracer (execve + open + openat + connect) |
| Analysis | `cmd/analysis/` | Event analysis pipeline — heuristic + optional LLM |
| Execve Tracer | `cmd/execve-tracer/` | Standalone execve tracer |
| Open Tracer | `cmd/open-tracer/` | Standalone open tracer |
| Openat Tracer | `cmd/openat-tracer/` | Standalone openat tracer |

### Analysis Component Internals

| Package | Path | Purpose |
|---------|------|---------|
| `interestingness` | `cmd/analysis/internal/interestingness/` | Scores event batches (0.0-1.0) for LLM gating |
| `llm` | `cmd/analysis/internal/llm/` | LLM backends: ollama, openai, anthropic, null |
| `incidents` | `cmd/analysis/internal/incidents/` | Labeled incident store with cosine similarity search |
| Alerts | `cmd/analysis/alert.go` | Alert storage with feedback mechanism |
| Processor | `cmd/analysis/processor.go` | Batch accumulator, interestingness scorer, LLM pipeline |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check (Elasticsearch, LLM status) |
| `/ingest` | POST | Ingest events (single or array) |
| `/ingest/batch` | POST | Ingest batched events |
| `/analyze` | POST | On-demand LLM analysis of a query string |
| `/actions/:hostname` | GET | Fetch pending heuristic actions for a host |
| `/api/alerts` | GET | List alerts (query: `since`, `min_verdict`, `limit`) |
| `/api/alerts/stats` | GET | Alert statistics (24h count, verdict breakdown, feedback) |
| `/api/alerts/:id/feedback` | POST | Submit feedback (`confirmed` or `false_positive`) |
| `/api/incidents` | GET | List labeled incidents |

### Alert Feedback

```bash
curl -X POST http://localhost:8080/api/alerts/<alert-id>/feedback \
  -H "Content-Type: application/json" \
  -d '{"feedback": "confirmed"}'
```

Confirmed alerts become labeled incidents in the RAG store, improving future analysis.

## Interestingness Gating

The interestingness scorer gates LLM analysis — only batches scoring above `LLM_THRESHOLD` (default 0.6) trigger LLM calls. This eliminates ~95% of unnecessary LLM invocations.

Scoring factors:
- Exec + network events in the same batch (+0.3)
- Download followed by network connection (+0.2)
- Network tool usage (+0.2)
- Temp directory execution (+0.3)
- Connections to mining/c2 ports (+0.25)
- Near-miss patterns (+0.15 each, max +0.45)
- Unknown binary execution (+0.15)
- Rapid unique port connections (+0.15)

The `null` backend (default) means zero external dependencies in production. Set `LLM_BACKEND=none` to run without LLM.

## Environment Variables

### Analysis Service

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_BACKEND` | `none` | LLM backend: `none`, `ollama`, `openai`, `anthropic` |
| `LLM_THRESHOLD` | `0.6` | Minimum interestingness score to invoke LLM (0.0-1.0) |
| `OLLAMA_ADDRESS` | `http://localhost:11434` | Ollama server address |
| `OLLAMA_MODEL` | `qwen2.5:7b` | Ollama analysis model |
| `ES_ADDRESSES` | `http://localhost:9200` | Elasticsearch addresses |
| `ES_INDEX` | `kb-events` | Elasticsearch events index |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `ANTHROPIC_MODEL` | `claude-3-haiku-20240307` | Anthropic model |
| `PROTOCOL` | `both` | Server protocol: `http`, `grpc`, or `both` |
| `GRPC_ADDRESS` | `:9090` | gRPC server address |
| `HTTP_ADDRESS` | `:8080` | HTTP server address |

### Agent

| Variable | Description |
|----------|-------------|
| `GRPC_ADDRESS` | gRPC server address (e.g., `localhost:9090`) |

## Project Structure

```
KernelHarbor/
├── bpf/                       # eBPF C programs
├── cmd/
│   ├── agent/                 # Unified tracer (execve + open + openat + connect)
│   ├── execve-tracer/         # Standalone execve tracer
│   ├── open-tracer/           # Standalone open tracer
│   ├── openat-tracer/         # Standalone openat tracer
│   └── analysis/              # Analysis pipeline
│       ├── main.go            # Entry point, config, server startup
│       ├── routes.go          # HTTP route handlers
│       ├── processor.go       # Batch processor + LLM pipeline
│       ├── alert.go           # Alert store with feedback
│       ├── event.go           # Event types + behavior summaries
│       ├── grpc.go            # gRPC handlers + heuristic patterns
│       ├── elastic.go         # Elasticsearch client
│       ├── state.go           # Package-level state
│       ├── bench_test.go      # Benchmarks + accuracy tests
│       ├── eval_test.go       # Evaluation framework
│       └── internal/
│           ├── interestingness/  # Batch scoring
│           ├── llm/              # LLM backends
│           └── incidents/        # Labeled incident store
├── proto/                     # Protocol Buffer definitions
├── deploy/                    # Docker Compose + Dockerfiles
├── scripts/                   # Utility scripts
├── Makefile
└── README.md
```

## Tests

```bash
# All unit tests
go test ./cmd/analysis/...

# Evaluation tests (no external services needed)
go test -run 'TestEval' ./cmd/analysis/...

# Benchmarks
./scripts/bench.sh

# Full test suite (requires Elasticsearch + Ollama)
ES_ADDRESSES=http://localhost:9200 OLLAMA_ADDRESS=http://localhost:11434 \
  go test -bench='Benchmark(ES|Ollama)' ./cmd/analysis/...
```

## Deployment

### Docker (AI Mode)

```bash
cd deploy
docker compose up -d
```

This starts Elasticsearch, Ollama, and the analysis service. The agent must run natively (requires eBPF + root).

### Heuristic-Only (Production)

No external dependencies — just the analysis binary and the agent binary:

```bash
cd cmd/analysis && go build -o analysis . && ./analysis
# In another terminal:
sudo GRPC_ADDRESS=localhost:9090 ./cmd/agent/agent
```

## License

MIT
