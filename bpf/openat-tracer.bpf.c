// go:build ignore
#include "vmlinux.h"
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

/*
 * REIMPLEMENTATION OF D_PATH
 */

#define MAX_PATH_DEPTH 20   // max number of path components (dentry levels) to walk
#define MAX_COMP_LEN   48   // max length of a single path component name

// per-CPU scratch buffer for collecting path components during the dentry walk.
struct path_scratch {
  char names[MAX_PATH_DEPTH][MAX_COMP_LEN]; // component names stored leaf-to-root during walk
  int  lens[MAX_PATH_DEPTH];                // strlen of each component (excluding NUL terminator)
  int  count;                               // number of components collected
  char output[256];                         // assembled path string (built root-to-leaf in phase 2)
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct path_scratch);
  __uint(max_entries, 1);
} path_scratch SEC(".maps");

// resolve_path: manually walk the dentry chain from 'dentry' up to 'root_dentry' (the process root),
// collecting path component names, then concatenate them in root-to-leaf order into 'buf'.
// this reimplements what the kernel's d_path() / bpf_d_path() does internally.
//
// parameters:
//   dentry, vfsmnt       — the starting path (e.g., the process CWD or the directory of a dirfd)
//   root_dentry, root_mnt — the process's root path (stop condition)
//   buf, buf_len          — output buffer for the resolved absolute path string
//
// returns 0 on success, -1 on failure.
static __always_inline int resolve_path(
    struct dentry *dentry, struct vfsmount *vfsmnt,
    struct dentry *root_dentry, struct vfsmount *root_mnt,
    char *buf, int buf_len)
{
  u32 zero = 0;
  struct path_scratch *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
  if (!scratch)
    return -1;

  scratch->count = 0;

  // phase 1: walk the dentry chain from leaf to root, collecting component names.
  // when we hit the root of a filesystem (dentry == d_parent), we check for a mount boundary:
  //   if there is a parent mount, we cross into it via mount->mnt_mountpoint and continue.
  //   if there is no parent mount (mnt_parent == mnt), we've reached the absolute root.
  #pragma unroll
  for (int i = 0; i < MAX_PATH_DEPTH; i++) {
    if (dentry == root_dentry && vfsmnt == root_mnt)
      break;

    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

    // potential stop condition: dentry is its own parent (filesystem root)
    if (dentry == parent) {
      // struct vfsmount is embedded inside struct mount at field 'mnt'.
      // to access the enclosing struct mount, we compute its address via scalar arithmetic
      // and use bpf_probe_read_kernel for all field reads. we avoid ***container_of*** / BPF_CORE_READ
      // because the verifier rejects pointer arithmetic that moves a pointer before its base object.
      unsigned long mount_addr = (unsigned long)vfsmnt
          - __builtin_offsetof(struct mount, mnt);

      struct mount *mnt_parent = NULL;
      bpf_probe_read_kernel(&mnt_parent, sizeof(mnt_parent),
          (void *)(mount_addr + __builtin_offsetof(struct mount, mnt_parent)));

      if (!mnt_parent || (unsigned long)mnt_parent == mount_addr)
        break;

      // read the mountpoint dentry in the parent filesystem
      struct dentry *mnt_mountpoint = NULL;
      bpf_probe_read_kernel(&mnt_mountpoint, sizeof(mnt_mountpoint),
          (void *)(mount_addr + __builtin_offsetof(struct mount, mnt_mountpoint)));
      if (!mnt_mountpoint)
        break;

      // cross the mount boundary: continue walking from the mountpoint dentry in the parent mount
      dentry = mnt_mountpoint;
      vfsmnt = (struct vfsmount *)((unsigned long)mnt_parent
          + __builtin_offsetof(struct mount, mnt));
      continue;
    }

    // read this component's name into the scratch buffer
    int idx = scratch->count;
    if (idx < 0 || idx >= MAX_PATH_DEPTH)
      break;

    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    int len = bpf_probe_read_kernel_str(scratch->names[idx], MAX_COMP_LEN, name);
    if (len <= 0)
      break;

    scratch->lens[idx] = len - 1;   // bpf_probe_read_kernel_str includes NUL terminator in return value
    scratch->count = idx + 1;

    // move up to the parent dentry
    dentry = parent;
  }

  // phase 2: concatenate the collected components in reverse order (root-to-leaf)
  int pos = 0;

  // special case: if no components were collected, the path is "/"
  if (scratch->count == 0) {
    scratch->output[0] = '/';
    scratch->output[1] = '\0';
    bpf_probe_read_kernel(buf, buf_len < 256 ? buf_len : 256, scratch->output);
    return 0;
  }

  #pragma unroll
  for (int i = 0; i < MAX_PATH_DEPTH; i++) {
    int idx = scratch->count - 1 - i;
    if (idx < 0)
      break;
    if (idx >= MAX_PATH_DEPTH)
      break;

    // write '/' separator.
    // both bounds are required: the upper bound prevents overflow, and the lower
    // bound is needed because the verifier cannot prove pos >= 0 after
    // `pos += comp_len` in a previous unrolled iteration
    if (pos < 0 || pos >= 255)
      break;
    pos &= 0xFF;
    // WHY DO WE USE `asm volatile("" : "+r"(pos));`?
    // we insert a no-op (blank string), and inform the compiler that the variable
    // pos was read and written to. this ensures that operations using any register that
    // pos resides in must wait until any writes are reflected, and prevents
    // any reordering of operations
    // ALTERNATIVELY, we could mark the variable pos as volatile in it's
    // declaration, but this adds unnecessary overhead
    asm volatile("" : "+r"(pos));
    scratch->output[pos] = '/';
    pos++;

    // copy the component name from the names array into the output buffer
    int comp_len = scratch->lens[idx];
    if (comp_len <= 0)
      continue;
    if (comp_len > MAX_COMP_LEN - 1)
      comp_len = MAX_COMP_LEN - 1;

    // ensure we don't overflow scratch->output[256]:
    if (pos + comp_len > 255)
      comp_len = 255 - pos;
    if (comp_len <= 0)
      break;

    pos &= 0xFF;
    asm volatile("" : "+r"(pos));
    if (pos > 256 - MAX_COMP_LEN)
      break;
    bpf_probe_read_kernel(&scratch->output[pos], comp_len & (MAX_COMP_LEN - 1),
        scratch->names[idx]);
    pos += comp_len;
  }

  // NUL-terminate.
  pos &= 0xFF;
  asm volatile("" : "+r"(pos));
  if (pos >= 0 && pos < 256)
    scratch->output[pos] = '\0';
  else
    scratch->output[255] = '\0';

  // copy the assembled path from scratch into the caller's buffer (e->dir_path)
  bpf_probe_read_kernel(buf, buf_len < 256 ? buf_len : 256, scratch->output);
  return 0;
}

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

  // collect information to resolve the directory path by manually walking the dentry chain
  struct task_struct *task = bpf_get_current_task_btf();
  e->dir_path_avail = false;

  // read the process root path — this is the stop condition for the dentry walk
  struct fs_struct *fs = BPF_CORE_READ(task, fs);
  struct dentry  *root_dentry = BPF_CORE_READ(fs, root.dentry);
  struct vfsmount *root_mnt   = BPF_CORE_READ(fs, root.mnt);

  struct dentry  *dentry = NULL;
  struct vfsmount *vfsmnt = NULL;

  if (e->dirfd == AT_FDCWD) {
    // resolve the process's current working directory
    dentry = BPF_CORE_READ(fs, pwd.dentry);
    vfsmnt = BPF_CORE_READ(fs, pwd.mnt);
  } else {
    // resolve the directory referred to by the file descriptor
    // walk task_struct->files->fdt->fd[dirfd] to get the struct file
    struct files_struct *files = BPF_CORE_READ(task, files);
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fd_array[e->dirfd]);
    if (f) {
      dentry = BPF_CORE_READ(f, f_path.dentry);
      vfsmnt = BPF_CORE_READ(f, f_path.mnt);
    }
  }

  if (dentry && vfsmnt) {
    int ret = resolve_path(dentry, vfsmnt, root_dentry, root_mnt,
                           e->dir_path, sizeof(e->dir_path));
    if (ret == 0)
      e->dir_path_avail = true;
  }

  bpf_ringbuf_submit(e, 0);
  return 0;
}
