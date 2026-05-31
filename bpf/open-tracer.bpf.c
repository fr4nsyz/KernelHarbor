// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "open.h"
#include "process.h"

char LICENSE[] SEC("license") = "GPL";

struct event {
	struct process_info proc;
	char filename[256];
	int flags;
	bool mode_avail;
	mode_t mode;
};

// ring buffer
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");  // place in BTF maps ELF section (https://docs.ebpf.io/linux/concepts/maps/)

/* NOTE: we assume the trace_event_raw_sys_enter struct to be of the following format:
*
*   struct trace_event_raw_sys_enter {
*   	struct trace_entry ent;
*   	long int id;
*   	long unsigned int args[6];
*   	char __data[0];
*   };
* 
* NOTE: we assume the following function header for the open syscall
*
*   int open(const char *path, int flags, ...
*                       mode_t mode  );
*
* mode is an optional argument
* this means that in the trace_event_raw_sys_enter struct:
*   args[0] is the name of the file being opened
*   args[1] is one of O_RDONLY, O_WRONLY, O_RDWR bitwise ORed with zero or more file creation flags (https://man7.org/linux/man-pages/man2/open.2.html)
*   args[2] is either nullptr, or a mode_t value indicating file permissions
*/

SEC("tracepoint/syscalls/sys_enter_open")
int handle_open(struct trace_event_raw_sys_enter *ctx) {
	struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	read_process_info(&e->proc);

	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

	e->flags = (int)ctx->args[1];

	if (e->flags & (O_CREAT | O_TMPFILE)) {
		e->mode = (mode_t)ctx->args[2];
		e->mode_avail = true;
	} else {
		e->mode_avail = false;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
