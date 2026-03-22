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

type Event struct {
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
}

func main() {
	// allow eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// load compiled objects
	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// attach to exec tracepoint
	tp, err := link.Tracepoint(
		"sched",
		"sched_process_exec",
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

	fmt.Println("👀 Listening for exec events... (Ctrl+C to stop)")

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

		fmt.Printf("PID: %d | COMM: %s | FILE: %s\n",
			e.Pid,
			bytes.TrimRight(e.Comm[:], "\x00"),
			bytes.TrimRight(e.Filename[:], "\x00"),
		)
	}
}
