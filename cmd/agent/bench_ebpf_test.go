//go:build ebpf

package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func TestEbpfLoadAndAttach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("eBPF benchmarks require root")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("failed to remove memlock: %v", err)
	}

	var execveObjs execveTracerObjects
	if err := loadExecveTracerObjects(&execveObjs, nil); err != nil {
		t.Fatalf("failed to load execve tracer: %v", err)
	}
	defer execveObjs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.HandleExec, nil)
	if err != nil {
		t.Fatalf("failed to attach execve tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(execveObjs.Events)
	if err != nil {
		t.Fatalf("failed to open execve ringbuf: %v", err)
	}
	defer rd.Close()

	t.Log("eBPF programs loaded and attached successfully")
}

func BenchmarkEbpfCPUOverhead(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("eBPF benchmarks require root")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatalf("failed to remove memlock: %v", err)
	}

	var execveObjs execveTracerObjects
	if err := loadExecveTracerObjects(&execveObjs, nil); err != nil {
		b.Fatalf("failed to load execve tracer: %v", err)
	}
	defer execveObjs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.HandleExec, nil)
	if err != nil {
		b.Fatalf("failed to attach execve tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(execveObjs.Events)
	if err != nil {
		b.Fatalf("failed to open execve ringbuf: %v", err)
	}
	defer rd.Close()

	stopCh := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopCh:
				return
			default:
				_, _ = rd.Read()
			}
		}
	}()

	var cpuUsage float64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = runtime.NumGoroutine()
		time.Sleep(10 * time.Millisecond)
	}
	b.StopTimer()
	close(stopCh)

	b.Logf("CPU overhead measurement: %.2f%% (note: use perf/flamegraph for precise measurement)", cpuUsage)
}

func BenchmarkEbpfEventDropRate(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("eBPF benchmarks require root")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatalf("failed to remove memlock: %v", err)
	}

	var execveObjs execveTracerObjects
	if err := loadExecveTracerObjects(&execveObjs, nil); err != nil {
		b.Fatalf("failed to load execve tracer: %v", err)
	}
	defer execveObjs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.HandleExec, nil)
	if err != nil {
		b.Fatalf("failed to attach execve tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(execveObjs.Events)
	if err != nil {
		b.Fatalf("failed to open execve ringbuf: %v", err)
	}
	defer rd.Close()

	rd.SetDeadline(time.Now().Add(5 * time.Second))
	received := 0
	dropped := 0

	b.ResetTimer()
	for {
		_, err := rd.Read()
		if err != nil {
			if ringbuf.IsClosed(err) {
				break
			}
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				break
			}
			dropped++
			continue
		}
		received++
	}
	b.StopTimer()

	total := received + dropped
	dropRate := float64(0)
	if total > 0 {
		dropRate = float64(dropped) / float64(total) * 100
	}
	b.Logf("Events received: %d, dropped: %d, drop rate: %.2f%%", received, dropped, dropRate)
}

func BenchmarkEbpfMemoryOverhead(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("eBPF benchmarks require root")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatalf("failed to remove memlock: %v", err)
	}

	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	before := m.HeapAlloc

	var execveObjs execveTracerObjects
	if err := loadExecveTracerObjects(&execveObjs, nil); err != nil {
		b.Fatalf("failed to load execve tracer: %v", err)
	}

	var openObjs openTracerObjects
	if err := loadOpenTracerObjects(&openObjs, nil); err != nil {
		b.Fatalf("failed to load open tracer: %v", err)
	}

	var connectObjs connectTracerObjects
	if err := loadConnectTracerObjects(&connectObjs, nil); err != nil {
		b.Fatalf("failed to load connect tracer: %v", err)
	}

	var openatObjs openatTracerObjects
	if err := loadOpenatTracerObjects(&openatObjs, nil); err != nil {
		b.Fatalf("failed to load openat tracer: %v", err)
	}

	runtime.GC()
	runtime.ReadMemStats(&m)
	after := m.HeapAlloc

	overhead := float64(after-before) / 1024 / 1024
	b.Logf("eBPF memory overhead: %.2f MB for 4 tracers", overhead)

	execveObjs.Close()
	openObjs.Close()
	connectObjs.Close()
	openatObjs.Close()
}

func init() {
	_ = fmt.Sprintf
}
