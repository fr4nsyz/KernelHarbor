#ifndef __PROCESS_H__
#define __PROCESS_H__

/* Zero an event struct before filling it so that unset trailing fields never
 * leak stale ring-buffer contents to userspace. The verifier rejects the
 * __builtin_memset intrinsic, so we zero byte-wise with a fully unrolled loop
 * (len is always a compile-time constant here).
 */
static __always_inline void zero_event(void *p, unsigned long len)
{
	volatile __u8 *dst = (volatile __u8 *)p;
#pragma clang loop unroll(full)
	for (unsigned long i = 0; i < len; i++) {
		dst[i] = 0;
	}
}

struct process_info {
	u32 pid;
	u32 ppid;
	u64 start_time_ns;
	u64 parent_start_time_ns;
	char comm[16];
	char parent_comm[16];
};

static __always_inline void read_process_info(struct process_info *proc)
{
	struct task_struct *task = bpf_get_current_task_btf();

	proc->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&proc->comm, sizeof(proc->comm));

	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	proc->ppid = BPF_CORE_READ(parent, tgid);
	proc->start_time_ns = BPF_CORE_READ(task, start_boottime);
	proc->parent_start_time_ns = BPF_CORE_READ(parent, start_boottime);
	bpf_probe_read_kernel(&proc->parent_comm, sizeof(proc->parent_comm),
	                       BPF_CORE_READ(parent, comm));
}

#endif
