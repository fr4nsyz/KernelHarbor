package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I ../../bpf/" execveTracer ../../bpf/execve-tracer.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I ../../bpf/" openTracer ../../bpf/open-tracer.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I ../../bpf/" connectTracer ../../bpf/connect-tracer.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I ../../bpf/" openatTracer ../../bpf/openat-tracer.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -I ../../bpf/" xdpBlocklist ../../bpf/xdp-blocklist.bpf.c
