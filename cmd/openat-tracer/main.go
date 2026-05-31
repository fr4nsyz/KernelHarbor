package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const AT_FDCWD = -100

type ProcessInfo struct {
	Pid               uint32
	Ppid              uint32
	StartTimeNs       uint64
	ParentStartTimeNs uint64
	Comm              [16]byte
	ParentComm        [16]byte
}

func generateGUID(pid uint32, startTimeNs uint64) string {
	h, _ := os.Hostname()
	if h == "" {
		h = "unknown"
	}
	return fmt.Sprintf("%s-%d-%d", h, pid, startTimeNs)
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

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := openatTracerObjects{}
	if err := loadOpenatTracerObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

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

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	fmt.Println("Listening for openat events... (Ctrl+C to stop)")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	go func() {
		<-stop
		fmt.Println("\nStopping...")
		rd.Close()
	}()

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

		comm := string(bytes.TrimRight(e.Proc.Comm[:], "\x00"))
		parentComm := string(bytes.TrimRight(e.Proc.ParentComm[:], "\x00"))
		filename := string(bytes.TrimRight(e.Filename[:], "\x00"))
		processGUID := generateGUID(e.Proc.Pid, e.Proc.StartTimeNs)
		parentGUID := generateGUID(e.Proc.Ppid, e.Proc.ParentStartTimeNs)

		fmt.Printf("\nPID: %d | COMM: %s | PPID: %d | PCOMM: %s\n", e.Proc.Pid, comm, e.Proc.Ppid, parentComm)
		fmt.Printf("GUID: %s | PGUID: %s\n", processGUID, parentGUID)

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
		fmt.Printf("FLAGS: %s\n", decodeOpenFlags(e.Flags))

		if e.ModeAvail {
			fmt.Printf("MODE: %d\n", e.Mode)
		}
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
