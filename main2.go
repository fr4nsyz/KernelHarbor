package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// match C struct exactly
const MAX_ARGS = 20
const ARG_LEN = 128

type Event struct {
	Pid       uint32
	Comm      [16]byte
	Filename  [256]byte
	Flags     uint32
	ModeAvail bool
	_         [3]byte // MATCH PADDING INSERTED IN EQUIVALENT C STRUCT
	Mode      uint32
}

func main() {
	// allow eBPF to lock memory
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// load compiled eBPF objects
	objs := openTracerObjects{}
	if err := loadOpenTracerObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// attach to sys_enter_execve
	tp, err := link.Tracepoint(
		"syscalls",
		"sys_enter_open",
		objs.HandleExec,
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	// open ring buffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	fmt.Println("👀 Listening for open events... (Ctrl+C to stop)")

	// handle Ctrl+C
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	go func() {
		<-stop
		fmt.Println("\nStopping...")
		rd.Close()
	}()

	// read events
	for {
		record, err := rd.Read()
		if err != nil {
			break
		}

		var e Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Println("parse error:", err)
			continue
		}

		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

		fmt.Printf("\nPID: %d | COMM: %s\n", e.Pid, comm)
		fmt.Printf("OPEN: %s\n", filename)

		fmt.Printf("FLAGS: %d\n", e.Flags)

		if e.ModeAvail {
			fmt.Printf("MODE: %d\n", e.Mode)
		}
	}
}
