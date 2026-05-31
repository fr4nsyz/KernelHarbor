package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I ../../bpf/" openatTracer ../../bpf/openat-tracer.bpf.c
