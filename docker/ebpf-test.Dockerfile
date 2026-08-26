FROM golang:1.25-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        iproute2 \
        iputils-ping \
        tcpdump \
        bpftool \
    && rm -rf /var/lib/apt/lists/*
