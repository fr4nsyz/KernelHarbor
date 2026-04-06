# Contributing to KernelHarbor

## Development

### Prerequisites

- Go 1.25+
- clang, llvm, libbpf-dev
- bpftool (usually in `linux-tools-$(uname -r)`)
- Elasticsearch 8.x (for integration tests)
- Ollama (for AI analysis tests)

### Building

```bash
# Build everything (generates vmlinux.h and eBPF Go bindings automatically)
make

# Or build individual components
make execve-tracer
make open-tracer
make openat-tracer
make analysis

# Clean all generated files and binaries
make clean
```

### Testing

```bash
# Unit tests
make test

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
