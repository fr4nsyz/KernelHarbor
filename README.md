# KernelHarbor

Linux kernel security monitoring: **Falco** + heuristic detection + optional LLM-powered analysis.

**Three-tier architecture:** Heuristic (Tier 1) → LLM analysis (Tier 2) → Periodic summaries (Tier 3)

**Credits:** [Kien Do](https://github.com/kienmarkdo), [Francois Coleongco](https://github.com/fr4nsyz), [John Tyler](https://github.com/john00003), [Mehar Klair](https://github.com/meharklair)

> KernelHarbor originally shipped a custom eBPF agent for kernel event collection. The default
> pipeline now uses **Falco + falcosidekick** for event collection, which is more robust and
> requires no custom eBPF compilation. The original custom eBPF agents (`cmd/agent/` and friends) are
> preserved in the repo and can still be built via `make agent` for those who prefer them.

## Architecture

### Three-Tier Detection Pipeline

```mermaid
graph TB
    subgraph "Event Source"
        F1[Falco - eBPF] -->|http_output| FS[falcosidekick]
        FS -->|webhook| SG[HMAC Signer :28079]
        SG -->|signed + X-KH-Signature-256| WH[Webhook :28080]
        WH -->|verify HMAC| CNV[Convert to Event]
    end

    subgraph "Tier 1: Heuristic (real-time)"
        CNV -->|POST /ingest| H1[Regex Pattern Matcher]
        H1 -->|match| H2[Action: KILL_PID / BLOCK_IP]
        H1 -->|no match| H3[Submit to Batch Processor]
    end

    subgraph "Tier 2: LLM (30s-5m delay)"
        H3 -->|batch| IS[Interestingness Scorer]
        IS -->|score < threshold| D1[Skip: no LLM call]
        IS -->|score >= threshold| EM[Embeddings]
        EM --> VS[Vector Search: similar incidents]
        VS --> LLM[LLM Backend]
        LLM -->|alerts only, no actions| AL[Alert Store]
        AL --> FB[User Feedback]
        FB -->|confirmed| RAG[Incident Store for future RAG]
    end

    subgraph "Persistence"
        AL --> ES[Elasticsearch kb-alerts index]
        ES -->|reload on startup| AL
    end

    subgraph "Tier 3: Periodic Summary"
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
```

**Key design decision:** The LLM never generates automatic actions. Only the heuristic engine (regex patterns) can produce `KILL_PID` and `BLOCK_IP`. The LLM produces alerts for human review, plus labeled incidents that improve future RAG.

| Tier | Trigger | Latency | Actions Produced |
|------|---------|---------|-----------------|
| 1: Heuristic | Regex match | Same HTTP response | `KILL_PID`, `BLOCK_IP` |
| 2: LLM | Interestingness >= threshold | 30s-5m | Alerts only |
| 3: Periodic Summary | Timer (configurable) | Hours | Dashboard summaries |

### Event Flow

```mermaid
sequenceDiagram
    participant F as Falco (eBPF)
    participant FS2 as falcosidekick
    participant SG as HMAC Signer
    participant WH as Webhook
    participant S as Analysis Server
    participant ES as Elasticsearch
    participant LLM as LLM Backend

    F->>FS2: http_output (Falco JSON)
    FS2->>SG: webhook POST
    SG->>SG: HMAC-SHA256(body, secret)
    SG->>WH: POST + X-KH-Signature-256
    WH->>WH: Verify HMAC (401 if invalid)
    WH->>WH: Convert to Event format
    WH->>S: POST /ingest
    S->>S: Regex heuristic check
    opt KH_API_KEY set
        S->>S: Verify X-API-Key header
    end
    S->>ES: Index alert to kb-alerts
    S->>S: Batch accumulator
    S->>S: Interestingness score
    alt score >= threshold
        S->>LLM: Analyze batch
        LLM-->>S: Verdict + evidence
        S->>S: Store alert
        S->>ES: Index LLM alert
    end
```

## Quick Start

### Prerequisites

```bash
# Go 1.25+ for building from source
# Node.js 22+ for the plugin / dashboard
# See: https://go.dev/dl/

# Falco + falcosidekick (for event collection)
# See: https://falco.org/docs/install/
# See: https://github.com/falcosecurity/falcosidekick

# Optional: Elasticsearch for alert persistence
docker run -d --name elasticsearch -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.17.4

# Optional: Ollama for local LLM
ollama serve
ollama pull nomic-embed-text
ollama pull qwen2.5:7b
```

### Install (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/fr4nsyz/KernelHarbor/main/kernelharbor-openclaw/install.sh | bash

cd ~/kernelharbor/kernelharbor-openclaw
./cli/status.mjs       # check status
./cli/dashboard.mjs    # open browser dashboard
```

### Build (manual)

```bash
make            # Build analysis service
make analysis   # Build analysis only
make agent      # Build legacy custom eBPF agent (optional, not needed for Falco)
make clean      # Remove binaries + generated files
```

### Run

```bash
# Terminal 1: Analysis service (heuristic-only by default, zero external deps)
cd cmd/analysis && ./analysis

# Terminal 2: Falco + falcosidekick (requires sudo for Falco)
sudo falco -r kernelharbor-openclaw/rules/kernelharbor-rules.yaml \
  -o json_output=true \
  -o http_output.enabled=true \
  -o http_output.url=http://localhost:2801/
falcosidekick

# Or via the OpenClaw plugin (recommended): see kernelharbor-openclaw/
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
| Analysis | `cmd/analysis/` | Event analysis pipeline: heuristic + optional LLM |
| OpenClaw Plugin | `kernelharbor-openclaw/` | Orchestrates Falco + falcosidekick + analysis |
| HMAC Signer | `kernelharbor-openclaw/signer.mjs` | HMAC-SHA256 signing proxy for pipeline auth |
| Falco Rules | `kernelharbor-openclaw/rules/` | Detection rules for Falco |
| Legacy Agent | `cmd/agent/` | Original custom eBPF tracer (optional, not needed for Falco) |

### Analysis Component Internals

| Package | Path | Purpose |
|---------|------|---------|
| `interestingness` | `cmd/analysis/internal/interestingness/` | Scores event batches (0.0-1.0) for LLM gating |
| `llm` | `cmd/analysis/internal/llm/` | LLM backends: ollama, openai, anthropic, null |
| `incidents` | `cmd/analysis/internal/incidents/` | Labeled incident store with cosine similarity search |
| Alerts | `cmd/analysis/alert.go` | Alert storage with feedback mechanism |
| Processor | `cmd/analysis/processor.go` | Batch accumulator, interestingness scorer, LLM pipeline |
| Elasticsearch | `cmd/analysis/elastic.go` | ES client, index mgmt, alert persistence & reload |

## API Endpoints

| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/health` | GET | Health check | No |
| `/ready` | GET | Readiness check (Elasticsearch, LLM status) | No |
| `/ingest` | POST | Ingest events (single or array) | X-API-Key |
| `/ingest/batch` | POST | Ingest batched events | X-API-Key |
| `/analyze` | POST | On-demand LLM analysis of a query string | X-API-Key |
| `/actions/:hostname` | GET | Fetch pending heuristic actions for a host | X-API-Key |
| `/api/alerts` | GET | List alerts (query: `since`, `min_verdict`, `limit`) | X-API-Key |
| `/api/alerts/stats` | GET | Alert statistics (24h count, verdict breakdown, feedback) | X-API-Key |
| `/api/alerts/:id/feedback` | POST | Submit feedback (`confirmed` or `false_positive`) | X-API-Key |
| `/api/incidents` | GET | List labeled incidents | X-API-Key |

Auth is enforced when `KH_API_KEY` is set. Empty key = no auth (backward compatible).

### Alert Feedback

```bash
curl -X POST http://localhost:8080/api/alerts/<alert-id>/feedback \
  -H "Content-Type: application/json" \
  -d '{"feedback": "confirmed"}'
```

Confirmed alerts become labeled incidents in the RAG store, improving future analysis.

## Security

### API Key Auth

Set `KH_API_KEY` on the analysis service. Clients must pass `X-API-Key` header on all
endpoints except `/health` and `/ready`.

```bash
export KH_API_KEY="your-secret-key"
```

### HMAC-SHA256 Pipeline Signing

Set `KH_SIGNING_SECRET` on the plugin. When enabled, the pipeline becomes:

```
Falco → falcosidekick → signer:28079 (HMAC-SHA256) → webhook:28080 (verify) → analysis
```

Requests without a valid `X-KH-Signature-256` header are rejected with 401.

```bash
export KH_SIGNING_SECRET="your-shared-secret"
```

## Interestingness Gating

The interestingness scorer gates LLM analysis. Only batches scoring above `LLM_THRESHOLD` (default 0.6) trigger LLM calls. This eliminates ~95% of unnecessary LLM invocations.

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
| `KH_API_KEY` | `` | API key for HTTP auth (empty = disabled) |
| `PROTOCOL` | `both` | Server protocol: `http`, `grpc`, or `both` |
| `GRPC_ADDRESS` | `:9090` | gRPC server address |
| `HTTP_ADDRESS` | `:8080` | HTTP server address |

### Plugin / Pipeline

| Variable | Default | Description |
|----------|---------|-------------|
| `KH_SIGNING_SECRET` | `` | HMAC secret for Falco → analysis pipeline (empty = disabled) |
| `KH_DASHBOARD_PORT` | `8181` | Dashboard server port |

## Project Structure

```
KernelHarbor/
├── bpf/                       # eBPF C programs (for reference, not built by default)
├── cmd/
│   ├── agent/                 # Legacy custom eBPF agent (optional)
│   ├── execve-tracer/         # Legacy standalone tracer (optional)
│   ├── open-tracer/           # Legacy standalone tracer (optional)
│   ├── openat-tracer/         # Legacy standalone tracer (optional)
│   └── analysis/              # Analysis pipeline
│       ├── main.go            # Entry point, config, server startup
│       ├── routes.go          # HTTP route handlers + auth middleware
│       ├── processor.go       # Batch processor + LLM pipeline
│       ├── alert.go           # Alert store with feedback
│       ├── event.go           # Event types + behavior summaries
│       ├── grpc.go            # gRPC handlers + heuristic patterns
│       ├── elastic.go         # Elasticsearch client + alert persistence
│       ├── state.go           # Package-level state
│       ├── bench_test.go      # Benchmarks + accuracy tests
│       ├── eval_test.go       # Evaluation framework
│       └── internal/
│           ├── interestingness/  # Batch scoring
│           ├── llm/              # LLM backends
│           └── incidents/        # Labeled incident store
├── proto/                     # Protocol Buffer definitions
├── kernelharbor-openclaw/     # OpenClaw plugin (Falco-based event collection)
│   ├── plugin.mjs             # Plugin entry: manages all subprocesses
│   ├── signer.mjs             # HMAC-SHA256 signing proxy
│   ├── cli/                   # CLI tools (setup, status, dashboard)
│   ├── dashboard/             # SPA dashboard (HTML + JS + CSS)
│   ├── rules/                 # Falco detection rules
│   ├── test/                  # E2E + smoke + HMAC tests
│   └── install.sh             # One-liner install script
├── deploy/                    # Docker Compose + Dockerfiles
├── scripts/                   # Utility scripts
├── Makefile
└── README.md
```

## Tests

```bash
# All unit tests
go test ./cmd/analysis/...

# OpenClaw E2E tests (analysis API, dashboard, plugin structure)
cd kernelharbor-openclaw && node test/e2e.mjs

# Pipeline smoke test (Falco webhook → analysis)
cd kernelharbor-openclaw && node test/smoke.mjs

# HMAC pipeline test (signer → webhook verification)
cd kernelharbor-openclaw && node test/e2e-hmac.mjs

# Evaluation tests (no external services needed)
go test -run 'TestEval' ./cmd/analysis/...

# Full test suite (requires Elasticsearch + Ollama)
ES_ADDRESSES=http://localhost:9200 OLLAMA_ADDRESS=http://localhost:11434 \
  go test -bench='Benchmark(ES|Ollama)' ./cmd/analysis/...
```

## Deployment

### Docker Compose

```bash
cd kernelharbor-openclaw
docker compose up -d elasticsearch analysis

# With Falco + falcosidekick:
docker compose --profile falco up -d

# With LLM (Ollama):
docker compose --profile llm up -d
```

### Heuristic-Only (Production)

No external dependencies, just the analysis binary:

```bash
cd cmd/analysis && go build -o analysis . && ./analysis
# Events received via HTTP :8080 from Falco + falcosidekick or the OpenClaw plugin
```

## Legacy Custom eBPF Agent

KernelHarbor originally shipped a custom eBPF agent. It's still available if you prefer
not to use Falco:

```bash
# Build requirements: clang, llvm, libbpf-dev, kernel headers
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r)  # Debian/Ubuntu

# Build
make agent

# Run (requires sudo)
sudo GRPC_ADDRESS=localhost:9090 ./cmd/agent/agent
```

The custom agent sends events via gRPC directly to the analysis service. This path
receives less maintenance but is preserved for compatibility.

## License

MIT
