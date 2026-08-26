#!/bin/bash
# Run eBPF generation + build + tests + XDP rig inside Docker (works on macOS hosts).
# Usage:
#   ./scripts/test-ebpf-docker.sh            # generate + build + vet + test
#   ./scripts/test-ebpf-docker.sh --xdp      # also run the netns XDP blocklist rig

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="kernelharbor/ebpf-test:latest"
DOCKERFILE="${REPO_ROOT}/docker/ebpf-test.Dockerfile"

docker info > /dev/null 2>&1 || { echo "Docker daemon not running"; exit 1; }

if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
    echo "Building $IMAGE..."
    docker build -f "$DOCKERFILE" -t "$IMAGE" "$REPO_ROOT"
fi

RUN_ARGS=(--rm --privileged -v "$REPO_ROOT":/src
    -v kernelharbor-gomod:/go/pkg/mod -v kernelharbor-gocache:/root/.cache/go-build
    -w /src "$IMAGE")

echo "== vmlinux.h from VM kernel BTF =="
docker run "${RUN_ARGS[@]}" bash -c '
    if [ ! -f bpf/vmlinux.h ]; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
        echo "generated bpf/vmlinux.h"
    else
        echo "bpf/vmlinux.h already present"
    fi'

echo "== go generate + build + vet + test (cmd/agent) =="
docker run "${RUN_ARGS[@]}" bash -c 'cd cmd/agent && go generate ./... && go build -o agent . && go vet ./... && go test ./...'

if [ "${1:-}" = "--xdp" ]; then
    echo "== XDP blocklist netns rig =="
    docker run "${RUN_ARGS[@]}" bash scripts/test-xdp-blocklist.sh
fi

echo "Done."
