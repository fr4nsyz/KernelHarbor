package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "agent/proto"
)

const maxReconnectDelay = 30 * time.Second
const initialReconnectDelay = 1 * time.Second

const MAX_ARGS = 20
const ARG_LEN = 128

const AT_FDCWD = -100

const (
	batchMaxEvents = 64
	batchInterval  = 500 * time.Millisecond
)

var (
	grpcAddr   = os.Getenv("GRPC_ADDRESS")
	httpAddr   = os.Getenv("HTTP_ADDRESS")
	authToken  = os.Getenv("GRPC_AUTH_TOKEN")
	hostName   = getHostName()
	agentPID   = uint32(os.Getpid())
	grpcConn   *grpc.ClientConn
	grpcClient pb.AgentServiceClient
	useGRPC    bool
	grpcMu     sync.RWMutex
	grpcClosed atomic.Bool
	httpClient *http.Client

	xdpInterfaces = parseXDPInterfaces(os.Getenv("XDP_INTERFACES"))
	xdpLoaded     atomic.Bool
	xdpLinks      []link.Link
	xdpObjs       xdpBlocklistObjects
)

type tokenAuth struct {
	token string
}

func (t tokenAuth) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + t.token}, nil
}

func (tokenAuth) RequireTransportSecurity() bool {
	return false
}

func getHostName() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

type ProcessInfo struct {
	Pid               uint32
	Ppid              uint32
	StartTimeNs       uint64
	ParentStartTimeNs uint64
	Comm              [16]byte
	ParentComm        [16]byte
}

type UnifiedEvent struct {
	Timestamp   time.Time `json:"@timestamp"`
	HostName    string    `json:"host.name"`
	EventType   string    `json:"event.type"`
	EventID     string    `json:"event.id"`
	ProcessGUID string    `json:"process.guid,omitempty"`
	ParentGUID  string    `json:"parent.guid,omitempty"`
	ProcessID   uint32    `json:"process.pid"`
	ParentPID   uint32    `json:"parent.pid,omitempty"`
	Comm        string    `json:"comm,omitempty"`

	ImagePath   string `json:"image.path,omitempty"`
	CommandLine string `json:"command.line,omitempty"`

	FilePath  string `json:"file.path,omitempty"`
	Flags     int32  `json:"flags,omitempty"`
	FlagsDesc string `json:"file.flags,omitempty"`
	Mode      uint32 `json:"file.mode,omitempty"`

	RemoteAddr string `json:"remote.address,omitempty"`
	RemotePort uint16 `json:"remote.port,omitempty"`
	LocalAddr  string `json:"local.address,omitempty"`
	LocalPort  uint16 `json:"local.port,omitempty"`
}

type ExecveEvent struct {
	Proc     ProcessInfo
	Filename [256]byte
	Argc     int32
	Args     [MAX_ARGS][ARG_LEN]byte
}

type OpenEvent struct {
	Proc      ProcessInfo
	Filename  [256]byte
	Flags     int32
	ModeAvail bool
	_         [3]byte
	Mode      uint32
}

type OpenatEvent struct {
	Proc         ProcessInfo
	Dirfd        int32
	Filename     [256]byte
	Flags        uint32
	ModeAvail    bool
	Pad0         [3]byte
	Mode         uint32
	DirPath      [256]byte
	DirPathAvail bool
	Pad1         [3]byte
}

type ConnectEvent struct {
	Proc       ProcessInfo
	Fd         int32
	Family     uint16
	IpLen      uint8
	Ip         [16]byte
	Port       uint16
	LocalIpLen uint8
	LocalIp    [16]byte
	LocalPort  uint16
}

type lpmKeyV4 struct {
	PrefixLen uint32
	Data      [4]byte
}

type lpmKeyV6 struct {
	PrefixLen uint32
	Data      [16]byte
}

type EventBatch struct {
	Events     []UnifiedEvent `json:"events"`
	HostName   string         `json:"host.name"`
	ReceivedAt time.Time      `json:"received.at"`
}

type Batcher struct {
	mu        sync.Mutex
	events    []UnifiedEvent
	timer     *time.Timer
	flushCh   chan []UnifiedEvent
	stopCh    chan struct{}
	send      func([]UnifiedEvent)
	maxEvents int
	interval  time.Duration
}

func NewBatcher() *Batcher {
	return newBatcherWithSend(sendBatch, batchInterval, batchMaxEvents)
}

func newBatcherWithSend(send func([]UnifiedEvent), interval time.Duration, maxEvents int) *Batcher {
	b := &Batcher{
		events:    make([]UnifiedEvent, 0, maxEvents),
		flushCh:   make(chan []UnifiedEvent, 4096),
		stopCh:    make(chan struct{}),
		send:      send,
		maxEvents: maxEvents,
		interval:  interval,
	}
	b.timer = time.AfterFunc(interval, b.timerFlush)
	b.timer.Stop()
	go b.run()
	return b
}

func (b *Batcher) Add(event UnifiedEvent) {
	b.mu.Lock()
	b.events = append(b.events, event)
	if len(b.events) >= b.maxEvents {
		b.flushLocked()
	} else if len(b.events) == 1 {
		b.timer.Reset(b.interval)
	}
	b.mu.Unlock()
}

func (b *Batcher) timerFlush() {
	b.mu.Lock()
	b.flushLocked()
	b.mu.Unlock()
}

func (b *Batcher) flushLocked() {
	if len(b.events) == 0 {
		return
	}
	batch := make([]UnifiedEvent, len(b.events))
	copy(batch, b.events)
	b.events = b.events[:0]
	b.timer.Stop()
	select {
	case b.flushCh <- batch:
	default:
		log.Printf("Batcher: flush channel full, dropping %d events", len(batch))
	}
}

func (b *Batcher) run() {
	for {
		select {
		case batch := <-b.flushCh:
			b.send(batch)
		case <-b.stopCh:
			b.mu.Lock()
			b.flushLocked()
			b.mu.Unlock()
			return
		}
	}
}

func (b *Batcher) Stop() {
	close(b.stopCh)
}

func sendBatch(events []UnifiedEvent) {
	if len(events) == 0 {
		return
	}

	pbEvents := make([]*pb.Event, len(events))
	for i, e := range events {
		pbEvents[i] = eventToPb(e)
	}

	if useGRPC {
		if sendViaGRPC(pbEvents) {
			return
		}
		log.Printf("gRPC send failed, falling back to HTTP")
	}

	sendViaHTTP(events)
}

func eventToPb(e UnifiedEvent) *pb.Event {
	return &pb.Event{
		Timestamp:   e.Timestamp.Format(time.RFC3339),
		HostName:    e.HostName,
		EventType:   e.EventType,
		EventId:     e.EventID,
		ProcessId:   e.ProcessID,
		Comm:        e.Comm,
		ImagePath:   e.ImagePath,
		CommandLine: e.CommandLine,
		FilePath:    e.FilePath,
		Flags:       e.Flags,
		Mode:        e.Mode,
		RemoteAddr:  e.RemoteAddr,
		RemotePort:  uint32(e.RemotePort),
		LocalAddr:   e.LocalAddr,
		LocalPort:   uint32(e.LocalPort),
		ProcessGuid: e.ProcessGUID,
		ParentGuid:  e.ParentGUID,
		ParentPid:   e.ParentPID,
		FlagsDesc:   e.FlagsDesc,
	}
}

func sendViaGRPC(pbEvents []*pb.Event) bool {
	grpcMu.RLock()
	if grpcClosed.Load() || grpcClient == nil {
		grpcMu.RUnlock()
		return false
	}
	client := grpcClient
	grpcMu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Ingest(ctx, &pb.IngestRequest{Events: pbEvents})
	if err != nil {
		log.Printf("gRPC Ingest failed: %v", err)
		return false
	}

	if resp.Accepted > 0 {
		log.Printf("gRPC: sent %d events, accepted %d", len(pbEvents), resp.Accepted)
	}
	if len(resp.Actions) > 0 {
		executeActions(resp.Actions)
	}
	return true
}

func sendViaHTTP(events []UnifiedEvent) {
	if httpAddr == "" {
		return
	}

	batch := EventBatch{
		Events:     events,
		HostName:   hostName,
		ReceivedAt: time.Now(),
	}

	data, err := json.Marshal(batch)
	if err != nil {
		log.Printf("HTTP: failed to marshal batch: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", httpAddr+"/ingest/batch", bytes.NewReader(data))
	if err != nil {
		log.Printf("HTTP: failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("HTTP: failed to send batch: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("HTTP: server returned %d", resp.StatusCode)
	} else {
		log.Printf("HTTP: sent %d events, status %d", len(events), resp.StatusCode)
	}

	var result struct {
		Accepted int          `json:"accepted"`
		Actions  []httpAction `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && len(result.Actions) > 0 {
		pbActions := make([]*pb.Action, len(result.Actions))
		for i, a := range result.Actions {
			pbActions[i] = &pb.Action{
				Id:         a.ID,
				ActionType: a.ActionType,
				Target:     a.Target,
				Reason:     a.Reason,
			}
		}
		executeActions(pbActions)
	}
}

type httpAction struct {
	ID         string `json:"id"`
	ActionType string `json:"action.type"`
	Target     string `json:"target"`
	Reason     string `json:"reason"`
}

func generateGUID(pid uint32, startTimeNs uint64) string {
	return fmt.Sprintf("%s-%d-%d", hostName, pid, startTimeNs)
}

func formatIP(ipBytes []byte) string {
	if len(ipBytes) == 4 {
		return net.IP(ipBytes).String()
	}
	if len(ipBytes) == 16 {
		return net.IP(ipBytes).String()
	}
	return ""
}

func parseXDPInterfaces(spec string) []string {
	var names []string
	for _, s := range strings.Split(spec, ",") {
		if s = strings.TrimSpace(s); s != "" {
			names = append(names, s)
		}
	}
	return names
}

func newLPMKeyV4(ip net.IP) lpmKeyV4 {
	var k lpmKeyV4
	k.PrefixLen = 32
	copy(k.Data[:], ip.To4())
	return k
}

func newLPMKeyV6(ip net.IP) lpmKeyV6 {
	var k lpmKeyV6
	k.PrefixLen = 128
	copy(k.Data[:], ip.To16())
	return k
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	if grpcAddr == "" {
		grpcAddr = os.Getenv("GRPC_ADDRESS")
	}

	useGRPC = grpcAddr != ""
	if httpAddr == "" {
		httpAddr = os.Getenv("HTTP_ADDRESS")
	}

	httpClient = &http.Client{Timeout: 15 * time.Second}

	var execveObjs execveTracerObjects
	var openObjs openTracerObjects
	var connectObjs connectTracerObjects
	var openatObjs openatTracerObjects

	if err := loadExecveTracerObjects(&execveObjs, nil); err != nil {
		log.Fatalf("failed to load execve tracer: %v", err)
	}
	defer execveObjs.Close()

	if err := loadOpenTracerObjects(&openObjs, nil); err != nil {
		log.Fatalf("failed to load open tracer: %v", err)
	}
	defer openObjs.Close()

	if err := loadConnectTracerObjects(&connectObjs, nil); err != nil {
		log.Fatalf("failed to load connect tracer: %v", err)
	}
	defer connectObjs.Close()

	if err := loadOpenatTracerObjects(&openatObjs, nil); err != nil {
		log.Fatalf("failed to load openat tracer: %v", err)
	}
	defer openatObjs.Close()

	if len(xdpInterfaces) > 0 {
		if err := loadXdpBlocklistObjects(&xdpObjs, nil); err != nil {
			log.Fatalf("failed to load xdp blocklist: %v", err)
		}
		defer xdpObjs.Close()
		defer closeXDP()
		xdpLoaded.Store(true)

		attached := 0
		for _, name := range xdpInterfaces {
			if err := attachXDP(xdpObjs.XdpBlocklist, name); err != nil {
				log.Printf("xdp: not attached on %s: %v", name, err)
				continue
			}
			attached++
		}
		if attached > 0 {
			fmt.Printf("XDP ingress blocklist active on %d interface(s): %s\n",
				attached, strings.Join(xdpInterfaces, ", "))
		} else {
			log.Printf("xdp: no interfaces attached (requested: %s)", strings.Join(xdpInterfaces, ", "))
		}
	}

	execveTp, err := link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.HandleExec, nil)
	if err != nil {
		log.Fatalf("failed to attach execve tracepoint: %v", err)
	}
	defer execveTp.Close()

	execveatTp, err := link.Tracepoint("syscalls", "sys_enter_execveat", execveObjs.HandleExecveat, nil)
	if err != nil {
		log.Fatalf("failed to attach execveat tracepoint: %v", err)
	}
	defer execveatTp.Close()

	openTp, err := link.Tracepoint("syscalls", "sys_enter_open", openObjs.HandleOpen, nil)
	if err != nil {
		log.Fatalf("failed to attach open tracepoint: %v", err)
	}
	defer openTp.Close()

	connectTp, err := link.Tracepoint("syscalls", "sys_enter_connect", connectObjs.HandleConnect, nil)
	if err != nil {
		log.Fatalf("failed to attach connect tracepoint: %v", err)
	}
	defer connectTp.Close()

	openatTp, err := link.Tracepoint("syscalls", "sys_enter_openat", openatObjs.HandleOpenat, nil)
	if err != nil {
		log.Fatalf("failed to attach openat tracepoint: %v", err)
	}
	defer openatTp.Close()

	execveRd, err := ringbuf.NewReader(execveObjs.Events)
	if err != nil {
		log.Fatalf("failed to open execve ringbuf: %v", err)
	}
	defer execveRd.Close()

	openRd, err := ringbuf.NewReader(openObjs.Events)
	if err != nil {
		log.Fatalf("failed to open open ringbuf: %v", err)
	}
	defer openRd.Close()

	connectRd, err := ringbuf.NewReader(connectObjs.Events)
	if err != nil {
		log.Fatalf("failed to open connect ringbuf: %v", err)
	}
	defer connectRd.Close()

	openatRd, err := ringbuf.NewReader(openatObjs.Events)
	if err != nil {
		log.Fatalf("failed to open openat ringbuf: %v", err)
	}
	defer openatRd.Close()

	fmt.Println("Agent listening for execve, open, openat, and connect events...")

	if useGRPC {
		go grpcReconnectLoop()
		go fetchActionsLoop()
	}

	batcher := NewBatcher()
	defer batcher.Stop()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go readExecveRingbuf(execveRd, batcher)
	go readOpenRingbuf(openRd, batcher)
	go readConnectRingbuf(connectRd, batcher)
	go readOpenatRingbuf(openatRd, batcher)

	<-ctx.Done()
	fmt.Println("Stopping...")
	grpcMu.Lock()
	if grpcConn != nil {
		grpcClosed.Store(true)
		grpcConn.Close()
	}
	grpcMu.Unlock()
	execveRd.Close()
	openRd.Close()
	connectRd.Close()
	openatRd.Close()
}

func readExecveRingbuf(rd *ringbuf.Reader, b *Batcher) {
	log.Println("execve reader started")
	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("execve reader exiting: %v", err)
			return
		}

		var e ExecveEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Println("execve parse error:", err)
			continue
		}

		if e.Proc.Pid == agentPID {
			log.Printf("execve skipping agent self (PID=%d)", e.Proc.Pid)
			continue
		}

		log.Printf("execve raw event: pid=%d ppid=%d comm=%s filename=%s argc=%d",
			e.Proc.Pid, e.Proc.Ppid, string(bytes.TrimRight(e.Proc.Comm[:], "\x00")),
			string(bytes.TrimRight(e.Filename[:], "\x00")), e.Argc)

		comm := string(bytes.TrimRight(e.Proc.Comm[:], "\x00"))
		filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

		var args []string
		for i := 0; i < int(e.Argc) && i < MAX_ARGS; i++ {
			arg := string(bytes.TrimRight(e.Args[i][:], "\x00"))
			if arg == "" {
				continue
			}
			args = append(args, arg)
		}

		commandLine := ""
		if len(args) > 0 {
			commandLine = args[0]
			if len(args) > 1 {
				commandLine += " " + joinArgs(args[1:])
			}
		}

		processGUID := generateGUID(e.Proc.Pid, e.Proc.StartTimeNs)
		parentGUID := generateGUID(e.Proc.Ppid, e.Proc.ParentStartTimeNs)

		event := UnifiedEvent{
			Timestamp:   time.Now().UTC(),
			HostName:    hostName,
			EventType:   "execve",
			EventID:     fmt.Sprintf("execve-%d-%d", e.Proc.Pid, time.Now().UnixNano()),
			ProcessGUID: processGUID,
			ParentGUID:  parentGUID,
			ProcessID:   e.Proc.Pid,
			ParentPID:   e.Proc.Ppid,
			Comm:        comm,
			ImagePath:   filename,
			CommandLine: commandLine,
		}

		printEvent(event)
		b.Add(event)
	}
}

func readOpenRingbuf(rd *ringbuf.Reader, b *Batcher) {
	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var e OpenEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Println("open parse error:", err)
			continue
		}

		if e.Proc.Pid == agentPID {
			continue
		}

		comm := string(bytes.TrimRight(e.Proc.Comm[:], "\x00"))
		filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

		processGUID := generateGUID(e.Proc.Pid, e.Proc.StartTimeNs)
		parentGUID := generateGUID(e.Proc.Ppid, e.Proc.ParentStartTimeNs)

		event := UnifiedEvent{
			Timestamp:   time.Now().UTC(),
			HostName:    hostName,
			EventType:   "open",
			EventID:     fmt.Sprintf("open-%d-%d", e.Proc.Pid, time.Now().UnixNano()),
			ProcessGUID: processGUID,
			ParentGUID:  parentGUID,
			ProcessID:   e.Proc.Pid,
			ParentPID:   e.Proc.Ppid,
			Comm:        comm,
			FilePath:    filename,
			Flags:       e.Flags,
			FlagsDesc:   decodeOpenFlags(uint32(e.Flags)),
		}

		if e.ModeAvail {
			event.Mode = e.Mode
		}

		printEvent(event)
		b.Add(event)
	}
}

func readConnectRingbuf(rd *ringbuf.Reader, b *Batcher) {
	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var e ConnectEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Println("connect parse error:", err)
			continue
		}

		if e.Proc.Pid == agentPID {
			continue
		}

		comm := string(bytes.TrimRight(e.Proc.Comm[:], "\x00"))

		if e.IpLen == 0 || e.IpLen > 16 {
			continue
		}

		var remoteAddr string
		if e.IpLen == 4 {
			remoteAddr = formatIP(e.Ip[:4])
		} else if e.IpLen == 16 {
			remoteAddr = formatIP(e.Ip[:16])
		}

		var localAddr string
		if e.LocalIpLen == 4 {
			localAddr = formatIP(e.LocalIp[:4])
		} else if e.LocalIpLen == 16 {
			localAddr = formatIP(e.LocalIp[:16])
		}

		processGUID := generateGUID(e.Proc.Pid, e.Proc.StartTimeNs)
		parentGUID := generateGUID(e.Proc.Ppid, e.Proc.ParentStartTimeNs)

		event := UnifiedEvent{
			Timestamp:   time.Now().UTC(),
			HostName:    hostName,
			EventType:   "connect",
			EventID:     fmt.Sprintf("connect-%d-%d", e.Proc.Pid, time.Now().UnixNano()),
			ProcessGUID: processGUID,
			ParentGUID:  parentGUID,
			ProcessID:   e.Proc.Pid,
			ParentPID:   e.Proc.Ppid,
			Comm:        comm,
			RemoteAddr:  remoteAddr,
			RemotePort:  e.Port,
			LocalAddr:   localAddr,
			LocalPort:   e.LocalPort,
		}

		printEvent(event)
		b.Add(event)
	}
}

func readOpenatRingbuf(rd *ringbuf.Reader, b *Batcher) {
	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var e OpenatEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Println("openat parse error:", err)
			continue
		}

		if e.Proc.Pid == agentPID {
			continue
		}

		comm := string(bytes.TrimRight(e.Proc.Comm[:], "\x00"))
		filename := string(bytes.TrimRight(e.Filename[:], "\x00"))
		dirPath := ""
		if e.DirPathAvail {
			dirPath = string(bytes.TrimRight(e.DirPath[:], "\x00"))
		}

		processGUID := generateGUID(e.Proc.Pid, e.Proc.StartTimeNs)
		parentGUID := generateGUID(e.Proc.Ppid, e.Proc.ParentStartTimeNs)

		event := UnifiedEvent{
			Timestamp:   time.Now().UTC(),
			HostName:    hostName,
			EventType:   "open",
			EventID:     fmt.Sprintf("openat-%d-%d", e.Proc.Pid, time.Now().UnixNano()),
			ProcessGUID: processGUID,
			ParentGUID:  parentGUID,
			ProcessID:   e.Proc.Pid,
			ParentPID:   e.Proc.Ppid,
			Comm:        comm,
			FilePath:    resolveOpenatPath(e.Dirfd, dirPath, filename),
			Flags:       int32(e.Flags),
			FlagsDesc:   decodeOpenFlags(e.Flags),
		}

		if e.ModeAvail {
			event.Mode = e.Mode
		}

		printEvent(event)
		b.Add(event)
	}
}

var colors = struct {
	execve, open, connect, reset string
}{
	execve:  "\033[0;32m",
	open:    "\033[0;34m",
	connect: "\033[0;35m",
	reset:   "\033[0m",
}

func printEvent(event UnifiedEvent) {
	var color string
	switch event.EventType {
	case "execve":
		color = colors.execve
	case "open":
		color = colors.open
	case "connect":
		color = colors.connect
	default:
		color = colors.reset
	}

	fmt.Printf("\n%s┌─ %s EVENT ─────────────────────────────────────────┐%s\n", color, strings.ToUpper(event.EventType), colors.reset)
	fmt.Printf("%s│%s PID: %d │ PPID: %d │ COMM: %s\n", color, colors.reset, event.ProcessID, event.ParentPID, event.Comm)
	if event.ProcessGUID != "" {
		fmt.Printf("%s│%s GUID: %s │ PGUID: %s\n", color, colors.reset, event.ProcessGUID, event.ParentGUID)
	}
	switch event.EventType {
	case "execve":
		fmt.Printf("%s│%s IMAGE: %s\n", color, colors.reset, event.ImagePath)
		fmt.Printf("%s│%s ARGS: %s\n", color, colors.reset, event.CommandLine)
	case "open":
		fmt.Printf("%s│%s FILE: %s\n", color, colors.reset, event.FilePath)
		fmt.Printf("%s│%s FLAGS: %s (%d)\n", color, colors.reset, event.FlagsDesc, event.Flags)
	case "connect":
		fmt.Printf("%s│%s DEST: %s:%d\n", color, colors.reset, event.RemoteAddr, event.RemotePort)
		if event.LocalAddr != "" || event.LocalPort != 0 {
			fmt.Printf("%s│%s SRC: %s:%d\n", color, colors.reset, event.LocalAddr, event.LocalPort)
		}
	}
	fmt.Printf("%s└──────────────────────────────────────────────────────┘%s\n", color, colors.reset)
}

func joinArgs(args []string) string {
	result := ""
	for i, arg := range args {
		if i > 0 {
			result += " "
		}
		result += arg
	}
	return result
}

func resolveOpenatPath(dirfd int32, dirPath, filename string) string {
	if strings.HasPrefix(filename, "/") {
		return filename
	}
	if dirPath != "" {
		if strings.HasSuffix(dirPath, "/") {
			return dirPath + filename
		}
		return dirPath + "/" + filename
	}
	return filename
}

func executeActions(actions []*pb.Action) {
	for _, a := range actions {
		switch a.ActionType {
		case "KILL_PID":
			pid, startNs, err := parseKillTarget(a.Target)
			if err != nil {
				log.Printf("exec: invalid KILL target %q: %v", a.Target, err)
				continue
			}
			if uint32(pid) == agentPID {
				log.Printf("exec: refusing to kill self (PID=%d)", pid)
				continue
			}
			if startNs > 0 {
				actual, err := processStartTimeNs(pid)
				if err != nil {
					log.Printf("exec: cannot verify PID %d start time, skipping: %v", pid, err)
					continue
				}
				tolerance := uint64(1 * time.Second)
				if diff := absDiff64(actual, startNs); diff > tolerance {
					log.Printf("exec: PID %d reused (expected start=%d, actual=%d), skipping", pid, startNs, actual)
					continue
				}
			}
			log.Printf("ACTION KILL_PID %d (reason: %s)", pid, a.Reason)
			if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
				log.Printf("ACTION KILL_PID %d failed: %v", pid, err)
			}
		case "BLOCK_IP":
			ip := a.Target
			if ip == "" {
				log.Printf("exec: empty BLOCK_IP target")
				continue
			}
			if _, ok := blockedIPs.Load(ip); ok {
				log.Printf("ACTION BLOCK_IP %s already blocked, skipping (reason: %s)", ip, a.Reason)
				continue
			}
			log.Printf("ACTION BLOCK_IP %s (reason: %s)", ip, a.Reason)
			ok := true
			for _, chain := range []string{"OUTPUT", "INPUT"} {
				if iptablesRuleExists(chain, ip) {
					log.Printf("ACTION BLOCK_IP %s: rule already present in %s", ip, chain)
					continue
				}
				cmd := exec.Command("iptables", "-w", "5", "-A", chain, "-s", ip, "-j", "DROP")
				if out, err := cmd.CombinedOutput(); err != nil {
					log.Printf("ACTION BLOCK_IP %s failed on %s: %v, output: %s", ip, chain, err, string(out))
					ok = false
				}
			}
			blockInXDP(ip)
			if ok {
				blockedIPs.Store(ip, true)
			} else {
				blockedIPs.Store(ip, true)
				log.Printf("ACTION BLOCK_IP %s partially applied", ip)
			}
		default:
			log.Printf("ACTION unknown type: %s", a.ActionType)
		}
	}
}

var blockedIPs sync.Map

func attachXDP(prog *ebpf.Program, ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	opts := link.XDPOptions{Program: prog, Interface: iface.Index}
	l, err := link.AttachXDP(opts)
	if err != nil {
		log.Printf("xdp: native mode unavailable on %s (%v), retrying with generic mode", ifaceName, err)
		opts.Flags = link.XDPGenericMode
		l, err = link.AttachXDP(opts)
	}
	if err != nil {
		return err
	}
	xdpLinks = append(xdpLinks, l)
	log.Printf("xdp: attached to %s", ifaceName)
	return nil
}

func closeXDP() {
	for _, l := range xdpLinks {
		l.Close()
	}
	xdpLinks = nil
}

func blockInXDP(ipStr string) {
	if !xdpLoaded.Load() {
		return
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Printf("ACTION BLOCK_IP %s: xdp skipped, invalid ip", ipStr)
		return
	}

	if v4 := ip.To4(); v4 != nil {
		key := newLPMKeyV4(v4)
		if err := xdpObjs.BlocklistV4.Update(&key, uint8(1), ebpf.UpdateAny); err != nil {
			log.Printf("ACTION BLOCK_IP %s: xdp v4 map update failed: %v", ipStr, err)
		} else {
			log.Printf("ACTION BLOCK_IP %s added to XDP ingress blocklist", ipStr)
		}
		return
	}

	key := newLPMKeyV6(ip)
	if err := xdpObjs.BlocklistV6.Update(&key, uint8(1), ebpf.UpdateAny); err != nil {
		log.Printf("ACTION BLOCK_IP %s: xdp v6 map update failed: %v", ipStr, err)
	} else {
		log.Printf("ACTION BLOCK_IP %s added to XDP ingress blocklist", ipStr)
	}
}

// parseKillTarget parses "<pid>@<start_ns>" (or a bare pid for legacy targets).
func parseKillTarget(target string) (int, uint64, error) {
	if idx := strings.IndexByte(target, '@'); idx >= 0 {
		pid, err := strconv.Atoi(target[:idx])
		if err != nil {
			return 0, 0, err
		}
		startNs, err := strconv.ParseUint(target[idx+1:], 10, 64)
		if err != nil {
			return 0, 0, err
		}
		return pid, startNs, nil
	}
	pid, err := strconv.Atoi(target)
	if err != nil {
		return 0, 0, err
	}
	return pid, 0, nil
}

// processStartTimeNs reads field 22 (starttime, clock ticks since boot) from
// /proc/<pid>/stat and converts it to nanoseconds.
func processStartTimeNs(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(data)
	end := strings.LastIndexByte(s, ')')
	if end < 0 || end+2 > len(s) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	// Fields after ") " start at field 3 (state); starttime is field 22 -> index 19.
	fields := strings.Fields(s[end+1:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("short /proc/%d/stat", pid)
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, err
	}
	return ticks * 1e9 / clkTck, nil
}

// clkTck mirrors sysconf(_SC_CLK_TCK). /proc/<pid>/stat starttime is always
// expressed in USER_HZ units, a kernel constant of 100 independent of
// CONFIG_HZ, so sysconf() returns 100 on every Linux build.
var clkTck = uint64(100)

func absDiff64(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

func iptablesRuleExists(chain, ip string) bool {
	err := exec.Command("iptables", "-w", "5", "-C", chain, "-s", ip, "-j", "DROP").Run()
	return err == nil
}

func fetchActionsLoop() {
	for {
		time.Sleep(5 * time.Second)
		grpcMu.RLock()
		client := grpcClient
		grpcMu.RUnlock()
		if client == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, err := client.FetchActions(ctx, &pb.ActionRequest{HostName: hostName})
		cancel()
		if err != nil {
			log.Printf("FetchActions failed: %v", err)
			continue
		}
		if len(resp.Actions) > 0 {
			executeActions(resp.Actions)
		}
	}
}

func grpcReconnectLoop() {
	delay := initialReconnectDelay
	for {
		conn, err := grpc.NewClient(grpcAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithPerRPCCredentials(tokenAuth{token: authToken}),
		)
		if err != nil {
			log.Printf("gRPC connection failed: %v", err)
			time.Sleep(delay)
			delay = min(delay*2, maxReconnectDelay)
			continue
		}

		client := pb.NewAgentServiceClient(conn)

		grpcMu.Lock()
		grpcConn = conn
		grpcClient = client
		grpcClosed.Store(false)
		grpcMu.Unlock()

		fmt.Printf("Connected to gRPC server: %s\n", grpcAddr)
		delay = initialReconnectDelay

		grpcMu.RLock()
		c := grpcClient
		closed := grpcClosed.Load()
		grpcMu.RUnlock()

		if closed {
			grpcMu.Lock()
			conn.Close()
			grpcMu.Unlock()
			time.Sleep(delay)
			delay = min(delay*2, maxReconnectDelay)
			continue
		}

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = c.Ingest(testCtx, &pb.IngestRequest{})
		cancel()

		if err != nil {
			grpcMu.Lock()
			grpcClosed.Store(true)
			conn.Close()
			grpcMu.Unlock()
			log.Printf("gRPC connection lost: %v, reconnecting...", err)
			time.Sleep(delay)
			delay = min(delay*2, maxReconnectDelay)
			continue
		}

		grpcMu.RLock()
		connState := grpcConn.GetState()
		grpcMu.RUnlock()

		_ = connState

		waitCtx, waitCancel := context.WithCancel(context.Background())
		go func() {
			for {
				grpcMu.RLock()
				state := grpcConn.GetState()
				grpcMu.RUnlock()
				if state.String() == "READY" {
					time.Sleep(1 * time.Second)
					continue
				}
				waitCancel()
				return
			}
		}()

		<-waitCtx.Done()

		grpcMu.Lock()
		if !grpcClosed.Load() {
			grpcClosed.Store(true)
			conn.Close()
		}
		grpcMu.Unlock()

		log.Printf("gRPC connection dropped, reconnecting...")
		time.Sleep(delay)
		delay = min(delay*2, maxReconnectDelay)
	}
}

func decodeOpenFlags(flags uint32) string {
	var parts []string

	switch flags & 0x3 {
	case 0:
		parts = append(parts, "O_RDONLY")
	case 1:
		parts = append(parts, "O_WRONLY")
	case 2:
		parts = append(parts, "O_RDWR")
	}

	flagBits := []struct {
		bit  uint32
		name string
	}{
		{0o100, "O_CREAT"},
		{0o200, "O_EXCL"},
		{0o400, "O_NOCTTY"},
		{0o1000, "O_TRUNC"},
		{0o2000, "O_APPEND"},
		{0o4000, "O_NONBLOCK"},
		{0o10000, "O_DSYNC"},
		{0o20000, "O_ASYNC"},
		{0o40000, "O_DIRECT"},
		{0o100000, "O_LARGEFILE"},
		{0o200000, "O_DIRECTORY"},
		{0o400000, "O_NOFOLLOW"},
		{0o1000000, "O_NOATIME"},
		{0o2000000, "O_CLOEXEC"},
		{0o10000000, "O_PATH"},
		{0o20200000, "O_TMPFILE"},
	}

	for _, fb := range flagBits {
		if fb.bit == 0o20200000 {
			if (flags & 0o20200000) == 0o20200000 {
				parts = append(parts, fb.name)
			}
			continue
		}
		if flags&fb.bit != 0 {
			parts = append(parts, fb.name)
		}
	}

	return strings.Join(parts, "|")
}
