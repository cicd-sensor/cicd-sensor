// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// process_hooks.bpf.h — fork and exec process lifecycle hooks.
//
// tp_btf gives typed task_struct/linux_binprm arguments on 5.15+, avoiding
// raw tracepoint layout parsing for process identity and argv capture.

// memfd execs are shmem/tmpfs-backed and use a "memfd:" dentry prefix.
#define TMPFS_MAGIC 0x01021994
#define MEMFD_DENTRY_PREFIX_LEN 6

// Copy the post-exec argv byte range as a NUL-separated blob. This is
// best-effort user memory: on fault, userspace gets argv_faulted without a
// partial blob.
static __always_inline void fill_exec_argv(struct exec_sample *sample, struct task_struct *task,
                                           struct linux_binprm *bprm)
{
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    unsigned long arg_start;
    unsigned long arg_end;
    __u64 total;
    __u32 to_copy;

    if (bprm)
        sample->argc = BPF_CORE_READ(bprm, argc);

    if (!mm)
        return;

    arg_start = BPF_CORE_READ(mm, arg_start);
    arg_end = BPF_CORE_READ(mm, arg_end);

    if (arg_end <= arg_start)
        return;

    total = arg_end - arg_start;
    if (total > ARGV_BLOB_LEN) {
        to_copy = ARGV_BLOB_LEN;
        sample->argv_truncated = 1;
    } else {
        to_copy = (__u32)total;
    }

    // Keep the verifier's range proof local to the helper argument.
    if (to_copy > ARGV_BLOB_LEN)
        to_copy = ARGV_BLOB_LEN;
    if (to_copy == 0)
        return;

    if (bpf_probe_read_user(sample->argv_blob, to_copy, (const void *)arg_start) < 0) {
        sample->argv_faulted = 1;
        sample->argv_blob_len = 0;
        return;
    }
    sample->argv_blob_len = to_copy;
}

// There is no dedicated memfd bit on linux_binprm. The practical signal is a
// tmpfs/shmem executable whose dentry name starts with "memfd:".
static __always_inline __u8 is_memfd_backed_exec(struct linux_binprm *bprm)
{
    const unsigned char *name_ptr;
    char prefix[MEMFD_DENTRY_PREFIX_LEN];
    __u64 sb_magic;

    if (!bprm)
        return 0;

    sb_magic = BPF_CORE_READ(bprm, file, f_inode, i_sb, s_magic);
    if (sb_magic != TMPFS_MAGIC)
        return 0;

    name_ptr = BPF_CORE_READ(bprm, file, f_path.dentry, d_name.name);
    if (!name_ptr)
        return 0;

    if (bpf_probe_read_kernel(prefix, sizeof(prefix), name_ptr) < 0)
        return 0;

    return prefix[0] == 'm' &&
           prefix[1] == 'e' &&
           prefix[2] == 'm' &&
           prefix[3] == 'f' &&
           prefix[4] == 'd' &&
           prefix[5] == ':';
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_sched_process_fork, struct task_struct *parent, struct task_struct *child)
{
    __u64 cgroup_id;

    // sched_process_fork also fires for new threads. Track process leaders
    // only; non-leader threads have pid != tgid.
    if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid)) {
        return 0;
    }

    cgroup_id = current_cgroup_id();
    if (!cgroup_is_tracked(cgroup_id))
        return 0;

    RESERVE_SAMPLE(sample, struct fork_sample, return 0);

    sample->kind = SAMPLE_KIND_FORK;
    sample->_pad = 0;
    sample->ts_ns = bpf_ktime_get_ns();
    sample->cgroup_id = cgroup_id;
    sample->child_start_boottime = BPF_CORE_READ(child, start_boottime);
    // parent may be a worker thread; resolve to its leader so the recorded
    // identity matches the parent's fork/exec entry.
    sample->parent_start_boottime = BPF_CORE_READ(parent, group_leader, start_boottime);
    sample->child_tgid = BPF_CORE_READ(child, tgid);
    sample->parent_tgid = BPF_CORE_READ(parent, tgid);

    bpf_ringbuf_submit(sample, 0);
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_sched_process_exec, struct task_struct *task, pid_t old_pid,
             struct linux_binprm *bprm)
{
    __u64 cgroup_id = current_cgroup_id();
    const char *filename;

    (void)old_pid;

    if (!cgroup_is_tracked(cgroup_id))
        return 0;

    RESERVE_SAMPLE(sample, struct exec_sample, return 0);

    sample->kind = SAMPLE_KIND_EXEC;
    sample->argv_truncated = 0;
    sample->argv_faulted = 0;
    sample->_pad0 = 0;
    sample->ts_ns = bpf_ktime_get_ns();
    sample->cgroup_id = cgroup_id;
    sample->start_boottime = BPF_CORE_READ(task, start_boottime);
    sample->tgid = BPF_CORE_READ(task, tgid);
    sample->is_memfd = 0;
    sample->_pad2[0] = 0;
    sample->_pad2[1] = 0;
    sample->_pad2[2] = 0;
    sample->argc = 0;
    sample->argv_blob_len = 0;
    zero_exec_path_bytes(sample->exec_path);
    zero_argv_blob_bytes(sample->argv_blob);

    filename = BPF_CORE_READ(bprm, filename);
    if (filename)
        bpf_probe_read_kernel_str(sample->exec_path, sizeof(sample->exec_path), filename);

    sample->is_memfd = is_memfd_backed_exec(bprm);

    fill_exec_argv(sample, task, bprm);

    bpf_ringbuf_submit(sample, 0);
    return 0;
}
