# AGENTS.md - KernelHarbor

## Build Commands

```bash
# Build analysis service
cd cmd/analysis && go build -o analysis .

# Build consolidated agent (execve + open + connect)
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
| `GRPC_ADDRESS` | `:9090` | analysis |
| `PROTOCOL` | `both` | analysis (http, grpc, or both) |

## Important Constraints

- **eBPF requires Linux**: Agent only works on Linux with kernel headers and root access
- **CI has no eBPF**: GitHub Actions runners don't support eBPF - integration tests are skipped in CI
- **External services required**: Analysis needs Elasticsearch 8.x and Ollama running
- **Code generation**: Run `cd cmd/agent && go generate ./...` to regenerate eBPF bindings
- **Kernel header path**: gen.go uses `/usr/src/kernels/6.19.8-200.fc43.x86_64` - update for other kernels
- **Proto generation**: Run `protoc --go_out=. --go-grpc_out=. proto/agent.proto` after editing proto

## Project Structure

```
cmd/agent/            # Consolidated tracer (execve + open + connect)
cmd/analysis/         # AI analysis pipeline (Go + gRPC)
proto/                # Protocol Buffer definitions
bpf/                  # eBPF C programs
scripts/              # test scripts
```

## Pre-commit

- Run `go fmt` before commits
- Ensure unit tests pass: `cd cmd/analysis && go test ./...`
