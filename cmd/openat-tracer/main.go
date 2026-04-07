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

type OpenatEvent struct {
	Pid           uint32
	Comm          [16]byte
	Filepath      [256]byte
	FilepathAvail bool
	_             [3]byte // padding to match C struct alignment
	Flags         uint32
	IMode         uint32
}

func main() {
	// allow eBPF to lock memory
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// load compiled eBPF objects
	objs := openatTracerObjects{}
	if err := loadOpenatTracerObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// attach fentry to security_file_open
	tp, err := link.AttachTracing(link.TracingOptions{
		Program: objs.HandleFileOpen,
	})
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

	fmt.Println("👀 Listening for openat events... (Ctrl+C to stop)")

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

		var e OpenatEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Println("parse error:", err)
			continue
		}

		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))

		fmt.Printf("\nPID: %d | COMM: %s\n", e.Pid, comm)

		if e.FilepathAvail {
			filepath := string(bytes.TrimRight(e.Filepath[:], "\x00"))
			fmt.Printf("PATH: %s\n", filepath)
		} else {
			fmt.Printf("PATH: (unavailable)\n")
		}

		fmt.Printf("FLAGS: %d\n", e.Flags)
		fmt.Printf("IMODE: %04o\n", e.IMode)
	}
}
