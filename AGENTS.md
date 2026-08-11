# AGENTS.md - KernelHarbor

## Build Commands

```bash
# Build analysis service
cd cmd/analysis && go build -o analysis .

# Build consolidated agent (execve + open + openat + connect)
cd cmd/agent && go build -o agent .
```

## Running

1. **Start analysis service** (terminal 1):
   ```bash
   cd cmd/analysis && ./analysis
   ```

2. **Start consolidated agent** (terminal 2, requires sudo):
   ```bash
   sudo GRPC_ADDRESS=localhost:9090 ./cmd/agent/agent
   ```

## Protocol

gRPC on port 9090 (configurable via `GRPC_ADDRESS`)

### Proto file
`proto/agent.proto` defines the service:
- `Ingest(Events)` - sends events to analysis
- `Analyze(query)` - queries AI analysis

## Key Environment Variables

| Variable | Default | Component |
|----------|---------|-----------|
| `ES_ADDRESSES` | `http://localhost:9200` | analysis |
| `OLLAMA_ADDRESS` | `http://localhost:11434` | analysis |
| `OLLAMA_MODEL` | `qwen2.5:7b` | analysis |
| `GRPC_ADDRESS` | `:9090` | analysis/agent |
| `GRPC_AUTH_TOKEN` | `` | analysis/agent (shared secret - set same on both sides) |
| `HTTP_ADDRESS` | `:8080` | analysis |
| `PROTOCOL` | `both` | analysis (http, grpc, or both) |

## Important Constraints

- **eBPF requires Linux**: Agent only works on Linux with kernel headers and root access
- **CI has no eBPF**: GitHub Actions runners don't support eBPF - integration tests are skipped in CI
- **External services required**: Analysis needs Elasticsearch 8.x and Ollama running
- **Code generation**: Run `make` (or `cd cmd/agent && go generate ./...`) to regenerate eBPF bindings. Same for standalone tracers (`cd cmd/execve-tracer && go generate ./...`, etc.). Each tracer dir (`cmd/execve-tracer`, `cmd/open-tracer`, `cmd/openat-tracer`) is its own Go module.
- **Proto generation**: Run `make proto` after editing `proto/agent.proto`. This regenerates both `cmd/agent/proto` (package `proto`) and `cmd/analysis/pb` (package `pb`) in one step.
- **Generated files are not committed**: eBPF object files (`cmd/*/*_bpf*.o`), binaries (`cmd/*/<name>`, `execve-tracer`, `open-tracer`), and `bpf/vmlinux.h` are gitignored. Generated `.go` bindings under `cmd/*/*_bpf*.go` are also produced by `go generate`; keep generated Go code out of commits unless a tracer module can't be built without it.

## Project Structure

```
cmd/agent/          # Consolidated tracer (execve + open + openat + connect)
cmd/execve-tracer/  # Standalone execve tracer
cmd/open-tracer/    # Standalone open tracer
cmd/openat-tracer/  # Standalone openat tracer
cmd/analysis/       # AI analysis pipeline (Go + gRPC)
proto/                # Protocol Buffer definitions
bpf/                  # eBPF C programs
scripts/              # test scripts
```

## Pre-commit

- Run `go fmt` before commits
- Ensure unit tests pass: `make test` (runs both analysis and agent tests)
