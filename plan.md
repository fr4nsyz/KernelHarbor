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
