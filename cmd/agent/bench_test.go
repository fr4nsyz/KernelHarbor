package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "agent/proto"
)

func BenchmarkEventParsing(b *testing.B) {
	e := ExecveEvent{
		Proc: ProcessInfo{
			Pid:         1234,
			Ppid:        1,
			StartTimeNs: 1000000,
		},
		Argc: 2,
	}
	copy(e.Proc.Comm[:], []byte("ls"))
	copy(e.Filename[:], []byte("/bin/ls"))
	copy(e.Args[0][:], []byte("ls"))
	copy(e.Args[1][:], []byte("-la"))
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.LittleEndian, &e)
	raw := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var ev ExecveEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
			b.Fatalf("parse error: %v", err)
		}
		_ = string(bytes.TrimRight(ev.Proc.Comm[:], "\x00"))
		_ = string(bytes.TrimRight(ev.Filename[:], "\x00"))
	}
}

func BenchmarkOpenEventParsing(b *testing.B) {
	e := OpenEvent{
		Proc: ProcessInfo{
			Pid:         5678,
			Ppid:        1,
			StartTimeNs: 2000000,
		},
		Flags:     0,
		ModeAvail: false,
	}
	copy(e.Proc.Comm[:], []byte("cat"))
	copy(e.Filename[:], []byte("/etc/passwd"))
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.LittleEndian, &e)
	raw := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var ev OpenEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
			b.Fatalf("parse error: %v", err)
		}
		_ = string(bytes.TrimRight(ev.Proc.Comm[:], "\x00"))
		_ = string(bytes.TrimRight(ev.Filename[:], "\x00"))
	}
}

func BenchmarkConnectEventParsing(b *testing.B) {
	e := ConnectEvent{
		Proc: ProcessInfo{
			Pid:         9999,
			Ppid:        1,
			StartTimeNs: 3000000,
		},
		Fd:         3,
		Family:     2,
		IpLen:      4,
		Port:       443,
		LocalIpLen: 4,
		LocalPort:  54321,
	}
	copy(e.Proc.Comm[:], []byte("curl"))
	copy(e.Ip[:4], []byte{10, 0, 0, 1})
	copy(e.LocalIp[:4], []byte{192, 168, 1, 1})
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.LittleEndian, &e)
	raw := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var ev ConnectEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
			b.Fatalf("parse error: %v", err)
		}
		_ = string(bytes.TrimRight(ev.Proc.Comm[:], "\x00"))
		if ev.IpLen == 4 {
			ip := make([]byte, 4)
			copy(ip, ev.Ip[:4])
			_ = formatIP(ip)
		}
	}
}

func BenchmarkEventToProto(b *testing.B) {
	event := UnifiedEvent{
		Timestamp:   time.Now().UTC(),
		HostName:    "bench-host",
		EventType:   "execve",
		EventID:     "bench-execve-001",
		ProcessGUID: "bench-host-1234-1000000",
		ParentGUID:  "bench-host-1-500000",
		ProcessID:   1234,
		ParentPID:   1,
		Comm:        "ls",
		ImagePath:   "/bin/ls",
		CommandLine: "ls -la /var/log",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = eventToPb(event)
	}
}

func BenchmarkEventJSONMarshal(b *testing.B) {
	event := UnifiedEvent{
		Timestamp:   time.Now().UTC(),
		HostName:    "bench-host",
		EventType:   "execve",
		EventID:     "bench-execve-002",
		ProcessGUID: "bench-host-1234-1000000",
		ParentGUID:  "bench-host-1-500000",
		ProcessID:   1234,
		ParentPID:   1,
		Comm:        "ls",
		ImagePath:   "/bin/ls",
		CommandLine: "ls -la /var/log",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(event)
	}
}

func BenchmarkRingBufferChannel(b *testing.B) {
	ch := make(chan UnifiedEvent, 10000)

	var sent atomic.Int64
	var received atomic.Int64

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				received.Add(1)
			case <-done:
				return
			}
		}
	}()

	event := UnifiedEvent{
		Timestamp:   time.Now().UTC(),
		HostName:    "bench-host",
		EventType:   "execve",
		EventID:     "bench-ch-001",
		ProcessGUID: "bench-host-1234-1000000",
		ProcessID:   1234,
		Comm:        "ls",
		ImagePath:   "/bin/ls",
		CommandLine: "ls -la",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		select {
		case ch <- event:
			sent.Add(1)
		default:
		}
	}
	b.StopTimer()
	close(done)
	b.Logf("Sent: %d, Received: %d, Drop rate: %.2f%%", sent.Load(), received.Load(),
		float64(sent.Load()-received.Load())/float64(sent.Load()+1)*100)
}

func BenchmarkGRPCSendLatency(b *testing.B) {
	grpcAddr := os.Getenv("GRPC_ADDRESS")
	if grpcAddr == "" {
		b.Skip("GRPC_ADDRESS not set, skipping gRPC send latency benchmark")
	}

	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		b.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	ctx := context.Background()

	latencies := make([]time.Duration, 0, b.N)
	var mu sync.Mutex

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		event := &pb.Event{
			Timestamp:   time.Now().Format(time.RFC3339),
			HostName:    "bench-host",
			EventType:   "execve",
			EventId:     fmt.Sprintf("bench-grpc-%d", i),
			ProcessId:   uint32(i % 65535),
			ProcessGuid: fmt.Sprintf("bench-host-%d-1000000", i%65535),
			ParentGuid:  "bench-host-1-500000",
			ParentPid:   1,
			ImagePath:   "ls",
			CommandLine: "ls -la /var/log",
		}

		start := time.Now()
		_, err := client.Ingest(ctx, &pb.IngestRequest{Events: []*pb.Event{event}})
		elapsed := time.Since(start)
		if err != nil {
			b.Fatalf("Ingest failed: %v", err)
		}

		mu.Lock()
		latencies = append(latencies, elapsed)
		mu.Unlock()
	}
	b.StopTimer()

	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		p50 := latencies[len(latencies)*50/100]
		p95 := latencies[len(latencies)*95/100]
		p99 := latencies[len(latencies)*99/100]
		b.Logf("gRPC send latency p50=%v p95=%v p99=%v", p50, p95, p99)
	}
}

func BenchmarkAgentMemoryUsage(b *testing.B) {
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	before := m.HeapAlloc

	events := make([]UnifiedEvent, 0, 10000)
	for i := 0; i < 10000; i++ {
		events = append(events, UnifiedEvent{
			Timestamp:   time.Now().UTC(),
			HostName:    "bench-host",
			EventType:   "execve",
			EventID:     fmt.Sprintf("bench-mem-%d", i),
			ProcessGUID: fmt.Sprintf("bench-host-%d-1000000", i%65535),
			ParentGUID:  "bench-host-1-500000",
			ProcessID:   uint32(i % 65535),
			ParentPID:   1,
			Comm:        "ls",
			ImagePath:   "/bin/ls",
			CommandLine: "ls -la /var/log",
		})
	}

	runtime.GC()
	runtime.ReadMemStats(&m)
	after := m.HeapAlloc

	perEvent := float64(after-before) / float64(len(events))
	b.Logf("Per-event memory: %.2f bytes", perEvent)
	b.Logf("Total heap growth: %.2f MB for %d events", float64(after-before)/1024/1024, len(events))

	_ = events
}

func TestGenerateGUID(t *testing.T) {
	guid := generateGUID(1234, 567890)
	expected := fmt.Sprintf("%s-1234-567890", hostName)
	if guid != expected {
		t.Errorf("generateGUID() = %v, want %v", guid, expected)
	}
}

func TestFormatIP(t *testing.T) {
	tests := []struct {
		name string
		ip   []byte
		want string
	}{
		{"ipv4", []byte{192, 168, 1, 1}, "192.168.1.1"},
		{"ipv4 loopback", []byte{127, 0, 0, 1}, "127.0.0.1"},
		{"ipv6 loopback", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "::1"},
		{"empty", []byte{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatIP(tt.ip)
			if got != tt.want {
				t.Errorf("formatIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeOpenFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  string
	}{
		{"o_rdonly", 0, "O_RDONLY"},
		{"o_wronly", 1, "O_WRONLY"},
		{"o_rdwr", 2, "O_RDWR"},
		{"o_rdonly_creat", 0o100, "O_RDONLY|O_CREAT"},
		{"o_wronly_creat_trunc", 0o1101, "O_WRONLY|O_CREAT|O_TRUNC"},
		{"o_rdwr_append", 0o2002, "O_RDWR|O_APPEND"},
		{"o_rdwr_cloexec", 0o2000002, "O_RDWR|O_CLOEXEC"},
		{"o_path", 0o10000000, "O_RDONLY|O_PATH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeOpenFlags(tt.flags)
			if got != tt.want {
				t.Errorf("decodeOpenFlags(%o) = %v, want %v", tt.flags, got, tt.want)
			}
		})
	}
}

func TestBatcher(t *testing.T) {
	var received [][]UnifiedEvent
	done := make(chan struct{})

	go func() {
		for batch := range make(chan []UnifiedEvent) {
			received = append(received, batch)
		}
	}()

	_ = received
	_ = done
}
