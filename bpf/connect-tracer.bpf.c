#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif


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
	u8 ip_len; // 4 or 16
	u8 ip[16]; // 4 bytes for ipv4, 16 bytes for ipv6    
	u16 port; 
	char comm[16];
};

SEC("tracepoint/syscalls/sys_enter_connect")

int handle_connect(struct trace_event_raw_sys_enter *ctx) {

	struct connect_event *e;

	struct sockaddr sa;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	
	void *user_sa = (void *)ctx->args[1];

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return 0;


	u32 pid = bpf_get_current_pid_tgid() >> 32;
	e->pid = pid;


	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// file descriptor
	e->fd = ctx->args[0];
	int socklen = ctx->args[2];

	// intial check to see if its valid and gets the family for branching after	
	if (socklen < sizeof(sa) ||
	    bpf_probe_read_user(&sa, sizeof(sa), user_sa) != 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}


	// ipv4 branch
	if (sa.sa_family == AF_INET) {
		if (socklen < sizeof(addr4) ||
		    bpf_probe_read_user(&addr4, sizeof(addr4), user_sa) != 0) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}

		e->family = AF_INET;
		e->ip_len = 4;
		e->port = bpf_ntohs(addr4.sin_port);
		__builtin_memcpy(e->ip, &addr4.sin_addr.s_addr, 4);
		bpf_ringbuf_submit(e, 0);
		return 0;
	}
	
	// ipv6 branch
	if (sa.sa_family == AF_INET6) {
		if (socklen < sizeof(addr6) ||
		    bpf_probe_read_user(&addr6, sizeof(addr6), user_sa) != 0) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}

		e->family = AF_INET6;
		e->ip_len = 16;
		e->port = bpf_ntohs(addr6.sin6_port);
		__builtin_memcpy(e->ip, &addr6.sin6_addr, 16);
		bpf_ringbuf_submit(e, 0);
		return 0;
	}

	bpf_ringbuf_discard(e, 0);
	return 0;
}




