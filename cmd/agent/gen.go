package main

//go:generate BPF2GO_CFLAGS="-O2 -g -Wall -I/usr/src/kernels/6.19.8-200.fc43.x86_64" go run github.com/cilium/ebpf/cmd/bpf2go -target bpfeb -cc clang execveTracer ../../bpf/execve-tracer.bpf.c
//go:generate BPF2GO_CFLAGS="-O2 -g -Wall -I/usr/src/kernels/6.19.8-200.fc43.x86_64" go run github.com/cilium/ebpf/cmd/bpf2go -target bpfeb -cc clang openTracer ../../bpf/open-tracer.bpf.c
//go:generate BPF2GO_CFLAGS="-O2 -g -Wall -I/usr/src/kernels/6.19.8-200.fc43.x86_64" go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang connectTracer ../../bpf/connect-tracer.bpf.c
