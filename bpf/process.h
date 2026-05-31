#ifndef __PROCESS_H__
#define __PROCESS_H__

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
