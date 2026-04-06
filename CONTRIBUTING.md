# Contributing to KernelHarbor

## Development

### Prerequisites

- Go 1.25+
- clang, llvm, libbpf-dev
- Linux headers (for eBPF)
- Elasticsearch 8.x (for integration tests)
- Ollama (for AI analysis tests)

### Building

```bash
# Build analysis server
cd cmd/analysis && go build -o analysis .

# Build eBPF tracers (requires Linux)
cd cmd/execve-tracer && go build -o execve-tracer .
cd cmd/open-tracer && go build -o open-tracer .
cd cmd/openat-tracer && go build -o openat-tracer .
```

### Testing

```bash
# Unit tests (all platforms)
cd cmd/analysis && go test -v ./...

# E2E tests (requires ES + Ollama)
./scripts/e2e-test.sh

# Integration tests (requires root + eBPF)
sudo ./scripts/integration-test.sh
```

## CI/CD Limitations

### GitHub Actions

**Important:** GitHub Actions runners (ubuntu-latest) do **not** support eBPF. This means:

- **Integration tests are skipped** in CI - they require a self-hosted runner with eBPF capabilities
- **eBPF tracer builds are tested** for compilation only, not runtime
- **E2E tests run** but without real kernel events

### Local Testing Required

For full test coverage, run tests locally:

```bash
# Full test suite
sudo ./scripts/integration-test.sh
```

### Recommended Local Setup

1. Use a VM or bare metal Linux machine with eBPF support
2. Or use a self-hosted GitHub Actions runner with eBPF

## Code Style

- Run `go fmt` before commits
- Add unit tests for new functionality
- Update README if adding new features

## Pull Requests

1. Ensure unit tests pass
2. Test E2E locally if possible
3. Update documentation as needed
