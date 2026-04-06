// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "open.h"

char LICENSE[] SEC("license") = "GPL";  // place license in corresponding ELF section

// struct to describe an invokation of the open syscall
struct event {
  u32 pid;              // the process ID of the process that is invoking the syscall
  char comm[16];        // the executable name of the process that is invoking the syscall
  char filename[256];   // the name of file that is being opened by the syscall
  int flags;            // the flags indicating the file creation and file status the syscall is opening the file with
  bool mode_avail;      // a boolean indicating if mode was provided to the syscall, and if anything is contained in event->mode
  // NOTE: padding is inserted here to account for mode_avail being only a single byte
  mode_t mode;          // the file mode bits related to permissions to be applied upon creating a new file
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

  e->pid = bpf_get_current_pid_tgid() >> 32;    // shift out the 32 bits representing thread group ID
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  // args[0] = filename
  const char *filename = (const char *)ctx->args[0];
  bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

  // args[1] = flags (scalar value, not a pointer)
  e->flags = (int)ctx->args[1];

  // args[2] = mode_t (only meaningful when O_CREAT is set in flags)
  if (e->flags & (O_CREAT | O_TMPFILE)) {
    e->mode = (mode_t)ctx->args[2];
    e->mode_avail = true;
  } else {
    e->mode_avail = false;
  }

  bpf_ringbuf_submit(e, 0);
  return 0;
}
