// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "open.h"

char LICENSE[] SEC("license") = "GPL";  // place license in corresponding ELF section

// struct to describe a file open event captured at security_file_open
struct event {
  u32 pid;              // the process ID of the process that is opening the file
  char comm[16];        // the executable name of the process that is opening the file
  char filepath[256];   // the resolved absolute path of the file being opened
  bool filepath_avail;  // whether filepath was successfully resolved via bpf_d_path
  // NOTE: padding is inserted here to account for filepath_avail being only a single byte
  int flags;            // the open flags (O_RDONLY, O_WRONLY, O_CREAT, etc.) from file->f_flags
  mode_t i_mode;        // the file's inode permission bits (from file->f_inode->i_mode)
};

// ring buffer
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");  // place in BTF maps ELF section (https://docs.ebpf.io/linux/concepts/maps/)

/* NOTE: we attach to security_file_open via fentry (BPF_PROG_TYPE_TRACING).
* This function is on the kernel's btf_allowlist_d_path, which allows us to
* use bpf_d_path to resolve the file's absolute path.
*
* security_file_open has the following signature:
*   int security_file_open(struct file *file)
*
* From struct file we extract:
*   f_path   - the resolved path (converted to string via bpf_d_path)
*   f_flags  - the open flags (O_RDONLY, O_WRONLY, O_CREAT, etc.)
*   f_inode->i_mode - the file's permission bits
*/

SEC("fentry/security_file_open")
int BPF_PROG(handle_file_open, struct file *file) {
  struct event *e;

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;    // shift out the 32 bits representing thread group ID
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  // resolve the file's absolute path from file->f_path
  e->filepath_avail = false;
  long ret = bpf_d_path(&file->f_path, e->filepath, sizeof(e->filepath));
  if (ret >= 0)
    e->filepath_avail = true;

  e->flags = BPF_CORE_READ(file, f_flags);
  e->i_mode = BPF_CORE_READ(file, f_inode, i_mode);

  bpf_ringbuf_submit(e, 0);
  return 0;
}
