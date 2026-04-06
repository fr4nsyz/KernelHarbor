// go:build ignore
#include "linux-headers/6.17.0-19/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "open.h"

char LICENSE[] SEC("license") = "GPL";  // place license in corresponding ELF section

#define AT_FDCWD -100

// struct to describe an invokation of the openat syscall
struct event {
  u32 pid;              // the process ID of the process that is invoking the syscall
  char comm[16];        // the executable name of the process that is invoking the syscall
  int dirfd;            // the file descriptor of the directory relative to which the pathname is resolved
  char filename[256];   // the name of file that is being opened by the syscall
  int flags;            // the flags indicating the file creation and file status the syscall is opening the file with
  bool mode_avail;      // a boolean indicating if mode was provided to the syscall, and if anything is contained in event->mode
  // NOTE: padding is inserted here to account for mode_avail being only a single byte
  mode_t mode;          // the file mode bits related to permissions to be applied upon creating a new file
  char dir_path[256];   // the resolved absolute path of dirfd (CWD when AT_FDCWD, or the directory referred to by dirfd)
  bool dir_path_avail;  // whether dir_path was successfully resolved
  // NOTE: padding is inserted here to account for mode_avail being only a single byte
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
* NOTE: we assume the following function header for the openat syscall
*
*   int openat(int dirfd, const char *pathname, int flags, ...
*                       mode_t mode  );
*
* mode is an optional argument
* this means that in the trace_event_raw_sys_enter struct:
*   args[0] is the directory file descriptor (AT_FDCWD for current working directory)
*   args[1] is the name of the file being opened
*   args[2] is one of O_RDONLY, O_WRONLY, O_RDWR bitwise ORed with zero or more file creation flags (https://man7.org/linux/man-pages/man2/openat.2.html)
*   args[3] is either nullptr, or a mode_t value indicating file permissions
*/

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
  struct event *e;

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;    // shift out the 32 bits representing thread group ID
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  // args[0] = dirfd (scalar value)
  e->dirfd = (int)ctx->args[0];

  // args[1] = filename
  const char *filename = (const char *)ctx->args[1];
  bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

  // args[2] = flags (scalar value, not a pointer)
  e->flags = (int)ctx->args[2];

  // args[3] = mode_t (only meaningful when O_CREAT is set in flags)
  if (e->flags & (O_CREAT | O_TMPFILE)) {
    e->mode = (mode_t)ctx->args[3];
    e->mode_avail = true;
  } else {
    e->mode_avail = false;
  }

  // resolve the directory path
  struct task_struct *task = bpf_get_current_task_btf();
  e->dir_path_avail = false;

  if (e->dirfd == AT_FDCWD) {
    // resolve the process's current working directory.
    // walk task_struct->fs->pwd using BPF_CORE_READ, which wraps bpf_probe_read_kernel
    // with BTF relocations so field offsets are adjusted at load time across kernel
    // versions (see https://nakryiko.com/posts/bpf-core-reference-guide/).
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    struct path *pwd = &fs->pwd;
    long ret = bpf_d_path(pwd, e->dir_path, sizeof(e->dir_path));
    if (ret >= 0)
      e->dir_path_avail = true;
  } else {
    // resolve the directory referred to by the file descriptor.
    // walk task_struct->files->fdt->fd[dirfd] to get the struct file, then resolve
    // its f_path with bpf_d_path.
    struct files_struct *files = BPF_CORE_READ(task, files);
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    struct file *f;
    bpf_probe_read_kernel(&f, sizeof(f), &fd_array[e->dirfd]);
    if (f) {
      struct path *fp = &f->f_path;
      long ret = bpf_d_path(fp, e->dir_path, sizeof(e->dir_path));
      if (ret >= 0)
        e->dir_path_avail = true;
    }
  }

  bpf_ringbuf_submit(e, 0);
  return 0;
}
