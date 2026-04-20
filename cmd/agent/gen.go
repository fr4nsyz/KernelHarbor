package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfeb -cc clang -cflags "-O2 -g -Wall" execveTracer ../../bpf/execve-tracer.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfeb -cc clang -cflags "-O2 -g -Wall" openTracer ../../bpf/open-tracer.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall" connectTracer ../../bpf/connect-tracer.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall" openatTracer ../../bpf/openat-tracer.bpf.c
