package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const AT_FDCWD = -100

type OpenatEvent struct {
	Pid          uint32
	Comm         [16]byte
	Dirfd        int32
	Filename     [256]byte
	Flags        uint32
	ModeAvail    bool
	Pad0         [3]byte // MATCH PADDING INSERTED IN EQUIVALENT C STRUCT
	Mode         uint32
	DirPath      [256]byte
	DirPathAvail bool
	Pad1         [3]byte // MATCH PADDING INSERTED IN EQUIVALENT C STRUCT
}

func main() {
	// allow eBPF to lock memory
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// load compiled eBPF objects
	objs := openatTracerObjects{}
	if err := loadOpenatTracerObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSizeStart: 1 << 26, // 64MB log buffer to capture full verifier output
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Verifier error: %+v\n", ve)
		} else {
			log.Fatal(err)
		}
		os.Exit(1)
	}
	defer objs.Close()

	// attach to sys_enter_openat
	tp, err := link.Tracepoint(
		"syscalls",
		"sys_enter_openat",
		objs.HandleOpenat,
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
		filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

		fmt.Printf("\nPID: %d | COMM: %s\n", e.Pid, comm)

		if e.Dirfd == AT_FDCWD {
			fmt.Printf("DIRFD: AT_FDCWD")
		} else {
			fmt.Printf("DIRFD: %d", e.Dirfd)
		}
		if e.DirPathAvail {
			dirPath := string(bytes.TrimRight(e.DirPath[:], "\x00"))
			fmt.Printf(" (%s)\n", dirPath)
		} else {
			fmt.Printf("\n")
		}

		fmt.Printf("OPENAT: %s\n", filename)

		fmt.Printf("FLAGS: %d\n", e.Flags)

		if e.ModeAvail {
			fmt.Printf("MODE: %d\n", e.Mode)
		}
	}
}
