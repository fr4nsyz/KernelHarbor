#include "linux-headers/6.17.0-19/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>


char LICENSE[] SEC("license") = "GPL";

// ring buffer
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");  // place in BTF maps ELF section (https://docs.ebpf.io/linux/concepts/maps/)



struct connect_event {
    u32 pid;
    u64 ts;
    int fd;
    u32 ip;     // Network byte order
    u16 port;   // Network byte order
    char comm[16];
};


SEC("tracepoint/syscalls/sys_enter_connect")

int handle_connect(struct trace_event_raw_sys_enter *ctx) {

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
	


  u32 pid = bpf_get_current_pid_tgid() >> 32;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
	


  // file descriptor
  u32 fd = ctx->args[0];
  bpf_probe_read_user_str(e->fd, sizeof(e->fd), fd)




  // 
  u64 addr_ptr = ctx->args[1];
  u32 addr_len = ctx->args[2];



	


}

