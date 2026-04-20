package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

var (
	grpcAddr   = os.Getenv("GRPC_ADDRESS")
	hostName   = getHostName()
	grpcConn   *grpc.ClientConn
	grpcClient pb.AgentServiceClient
	sendToAPI  bool
	grpcMu     sync.RWMutex
	grpcClosed atomic.Bool
)

func getHostName() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

type UnifiedEvent struct {
	Timestamp time.Time `json:"@timestamp"`
	HostName  string    `json:"host.name"`
	EventType string    `json:"event.type"`
	EventID   string    `json:"event.id"`
	ProcessID uint32    `json:"process.pid"`
	Comm      string    `json:"comm,omitempty"`

	ImagePath   string `json:"image.path,omitempty"`
	CommandLine string `json:"command.line,omitempty"`

	FilePath string `json:"file.path,omitempty"`
	Flags    int32  `json:"flags,omitempty"`
	Mode     uint32 `json:"mode,omitempty"`

	RemoteAddr string `json:"remote.addr,omitempty"`
	RemotePort uint16 `json:"remote.port,omitempty"`
	LocalAddr  string `json:"local.addr,omitempty"`
	LocalPort  uint16 `json:"local.port,omitempty"`
}

type ExecveEvent struct {
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
	Argc     int32
	Args     [MAX_ARGS][ARG_LEN]byte
}

type OpenEvent struct {
	Pid       uint32
	Comm      [16]byte
	Filename  [256]byte
	Flags     int32
	ModeAvail bool
	_         [3]byte
	Mode      uint32
}

type OpenatEvent struct {
	Pid          uint32
	Comm         [16]byte
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
	Pid        uint32
	Comm       [16]byte
	Fd         int32
	Family     uint16
	IpLen      uint8
	Ip         [16]byte
	Port       uint16
	LocalIpLen uint8
	LocalIp    [16]byte
	LocalPort  uint16
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

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

	execveTp, err := link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.HandleExec, nil)
	if err != nil {
		log.Fatalf("failed to attach execve tracepoint: %v", err)
	}
	defer execveTp.Close()

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

	if grpcAddr != "" {
		sendToAPI = true
		go grpcReconnectLoop()
	} else {
		fmt.Println("GRPC_ADDRESS not set, events will only be printed")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	go func() {
		<-stop
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
	}()

	go readExecveRingbuf(execveRd)
	go readOpenRingbuf(openRd)
	go readConnectRingbuf(connectRd)
	go readOpenatRingbuf(openatRd)

	<-stop
}

func readExecveRingbuf(rd *ringbuf.Reader) {
	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		var e ExecveEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Println("execve parse error:", err)
			continue
		}

		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
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

		event := UnifiedEvent{
			Timestamp:   time.Now().UTC(),
			HostName:    hostName,
			EventType:   "execve",
			EventID:     fmt.Sprintf("execve-%d-%d", e.Pid, time.Now().UnixNano()),
			ProcessID:   e.Pid,
			Comm:        comm,
			ImagePath:   filename,
			CommandLine: commandLine,
		}

		printEvent(event)
		if sendToAPI {
			sendEventToAPI(event)
		}
	}
}

func readOpenRingbuf(rd *ringbuf.Reader) {
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

		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

		event := UnifiedEvent{
			Timestamp: time.Now().UTC(),
			HostName:  hostName,
			EventType: "open",
			EventID:   fmt.Sprintf("open-%d-%d", e.Pid, time.Now().UnixNano()),
			ProcessID: e.Pid,
			Comm:      comm,
			FilePath:  filename,
			Flags:     e.Flags,
		}

		if e.ModeAvail {
			event.Mode = e.Mode
		}

		printEvent(event)
		if sendToAPI {
			sendEventToAPI(event)
		}
	}
}

func readConnectRingbuf(rd *ringbuf.Reader) {
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

		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))

		if e.IpLen == 0 || e.IpLen > 16 {
			continue
		}

		var remoteAddr string
		if e.IpLen == 4 {
			ip := make([]byte, 4)
			copy(ip, e.Ip[:4])
			remoteAddr = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
		} else if e.IpLen == 16 {
			ip := make([]byte, 16)
			copy(ip, e.Ip[:16])
			remoteAddr = fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
				ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
		}

		var localAddr string
		if e.LocalIpLen == 4 {
			ip := make([]byte, 4)
			copy(ip, e.LocalIp[:4])
			localAddr = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
		} else if e.LocalIpLen == 16 {
			ip := make([]byte, 16)
			copy(ip, e.LocalIp[:16])
			localAddr = fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
				ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
		}

		event := UnifiedEvent{
			Timestamp:  time.Now().UTC(),
			HostName:   hostName,
			EventType:  "connect",
			EventID:    fmt.Sprintf("connect-%d-%d", e.Pid, time.Now().UnixNano()),
			ProcessID:  e.Pid,
			Comm:       comm,
			RemoteAddr: remoteAddr,
			RemotePort: e.Port,
			LocalAddr:  localAddr,
			LocalPort:  e.LocalPort,
		}

		printEvent(event)
		if sendToAPI {
			sendEventToAPI(event)
		}
	}
}

func readOpenatRingbuf(rd *ringbuf.Reader) {
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

		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		filename := string(bytes.TrimRight(e.Filename[:], "\x00"))
		dirPath := ""
		if e.DirPathAvail {
			dirPath = string(bytes.TrimRight(e.DirPath[:], "\x00"))
		}

		event := UnifiedEvent{
			Timestamp: time.Now().UTC(),
			HostName:  hostName,
			EventType: "open",
			EventID:   fmt.Sprintf("openat-%d-%d", e.Pid, time.Now().UnixNano()),
			ProcessID: e.Pid,
			Comm:      comm,
			FilePath:  resolveOpenatPath(e.Dirfd, dirPath, filename),
			Flags:     int32(e.Flags),
		}

		if e.ModeAvail {
			event.Mode = e.Mode
		}

		printEvent(event)
		if sendToAPI {
			sendEventToAPI(event)
		}
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
	fmt.Printf("%s│%s  PID: %d  │  COMM: %s\n", color, colors.reset, event.ProcessID, event.Comm)
	switch event.EventType {
	case "execve":
		fmt.Printf("%s│%s  IMAGE: %s\n", color, colors.reset, event.ImagePath)
		fmt.Printf("%s│%s  ARGS:  %s\n", color, colors.reset, event.CommandLine)
	case "open":
		fmt.Printf("%s│%s  FILE:  %s\n", color, colors.reset, event.FilePath)
		fmt.Printf("%s│%s  FLAGS: %d\n", color, colors.reset, event.Flags)
	case "connect":
		fmt.Printf("%s│%s  DEST:  %s:%d\n", color, colors.reset, event.RemoteAddr, event.RemotePort)
		if event.LocalAddr != "" || event.LocalPort != 0 {
			fmt.Printf("%s│%s  SRC:   %s:%d\n", color, colors.reset, event.LocalAddr, event.LocalPort)
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

func sendEventToAPI(event UnifiedEvent) {
	grpcMu.RLock()
	if grpcClosed.Load() || grpcClient == nil {
		grpcMu.RUnlock()
		return
	}

	pbEvent := &pb.Event{
		Timestamp:   event.Timestamp.Format(time.RFC3339),
		HostName:    event.HostName,
		EventType:   event.EventType,
		EventId:     event.EventID,
		ProcessId:   event.ProcessID,
		Comm:        event.Comm,
		ImagePath:   event.ImagePath,
		CommandLine: event.CommandLine,
		FilePath:    event.FilePath,
		Flags:       event.Flags,
		Mode:        event.Mode,
		RemoteAddr:  event.RemoteAddr,
		RemotePort:  uint32(event.RemotePort),
		LocalAddr:   event.LocalAddr,
		LocalPort:   uint32(event.LocalPort),
	}

	client := grpcClient
	grpcMu.RUnlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		grpcMu.RLock()
		if grpcClosed.Load() {
			grpcMu.RUnlock()
			return
		}
		resp, err := client.Ingest(ctx, &pb.IngestRequest{Events: []*pb.Event{pbEvent}})
		grpcMu.RUnlock()

		if err != nil {
			log.Printf("Failed to send event: %v", err)
			return
		}

		if resp.Accepted > 0 {
			fmt.Printf("Event sent successfully\n")
		} else {
			fmt.Printf("Server rejected event\n")
		}
	}()
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

func grpcReconnectLoop() {
	delay := initialReconnectDelay
	for {
		conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = client.Ingest(testCtx, &pb.IngestRequest{})
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

		break
	}
}
