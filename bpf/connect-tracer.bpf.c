#include "vmlinux.h"
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
	int fd;
	u16 family;
	u32 ip;     // Network byte order
	u16 port;   // Network byte order
	char comm[16];
};


SEC("tracepoint/syscalls/sys_enter_connect")

int handle_connect(struct trace_event_raw_sys_enter *ctx) {

	struct connect_event *e;
	struct sockaddr_in addr_in;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return 0;



	u32 pid = bpf_get_current_pid_tgid() >> 32;
	e->pid = pid;


	bpf_get_current_comm(&e->comm, sizeof(e->comm));



	// file descriptor
	e->fd = ctx->args[0];
	//bpf_probe_read_user_str(e->fd, sizeof(e->fd), fd)

	if (bpf_probe_read_user(&addr_in, sizeof(addr_in), (void*)ctx->args[1]) < 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	if (addr_in.sin_family != 2) { // right now 2 is for ipv4 only processing that
		bpf_ringbuf_discard(e, 0);
		return 0;
	}



	e->family = addr_in.sin_family; 
	e->port = addr_in.sin_port;
	e->ip = addr_in.sin_addr.s_addr;

	bpf_ringbuf_submit(e,0);
	return 0;



}

