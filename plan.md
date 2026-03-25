## Prep & Tooling

**Goal:** Set up the environment for kernel-level monitoring.

- **Environment setup**
  - Linux VM or container
  - Install `clang` + `llvm` (required for eBPF)
  - Install `bcc` or `bpftrace` for prototyping

- **Programming stack**
  - eBPF: Good ol' C
  - eBPF loader: Go (`cilium/ebpf`) or Rust (`aya`)
  - Backend: Go
  - Detection: mix of LLMs, heuristics (e.g. IP blacklists or binary scans if the user pulls an external)

---

## eBPF Syscall Hooking
**Goal:** Capture minimal system events for reverse shell detection.

**Syscalls to monitor:**
- `execve` => process execution
- `connect` => network connections initiated
- `clone` / `fork` => suspicious process spawning
- optionally: `open` / `openat` => file modifications?

**Steps:**
1. Write an eBPF program to hook `execve`.
2. Log the following:
   - PID & Parent PID
   - Executable path & command line
   - Timestamp
3. Send logs to a user-space program (Backend).

**Deliverable:** eBPF agent that captures real-time logs of process executions and network connections.

---

## Streaming + Backend
**Goal:** Centralize events for analysis.

1. Build a backend service:
   - Use gRPC to receive events from agents
2. Store events:
   - ElasticSearch
3. Enrich events:
   - Map PID => Parent PID => Executable
   - Collect process metadata (`/proc/<pid>/cmdline`)

**Deliverable:** Multi-host events streamed centrally, ready for AI detection.

I think especially the metadata interpretation would be a good use for an LLM.

## Testing
**Goal:** Use tests to verify expected behaviour of eBPF syscall programs, host side loaders, and remote host analysis.

### eBPF Syscall Program Testing
Tests for eBPF syscall programs will reside in `bpf_tests/` and be written in C.

**eBPF test programs should verify the following behaviour:**
- the eBPF program correctly hooks when the corresponding syscall in invoked
- the syscall arguments are correctly captured and translated to an internal representation (a struct used by the eBPF program)
- the syscall arguments are correctly written for the host loader program running on the same machine to read

**Future work:** 
- measure or verify performance of eBPF syscall program under load (e.g., is ring buffer large enough? do syscalls get dropped?)

### Host Program Testing
Tests for host programs will reside in the same directory as the host programs, be named "<name-of-file-being-tested>_test.go", and be written in Go.
This allows for us to take advantage of Go's unit testing features.

**Host test programs should verify the following behaviour:**
- the host program correctly reads a mocked struct
- the host program correctly reports an invalid mocked struct (?) (e.g., an execve struct that reports 3 args in argc, but only 2 non-null pointers appear in argv)
- the host program correctly formats reported syscall and it's arguments into text
TODO: upon implementation of any telemetry and communication to the remote host, the testing plan should be expanded upon

**Future work:**
- measure or verify performance of host program under load (e.g., is ring buffer large enough? do syscalls get dropped?)

### Remote Host Analysis Program Testing
TODO
