// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// common_helpers.bpf.h — shared primitives used by BPF hook domains.

// vmlinux.h does not include AF_* macros from uapi/linux/socket.h.
#define AGENT_AF_INET 2
#define AGENT_AF_INET6 10
#define AGENT_AF_UNIX 1

static __always_inline void note_ringbuf_drop(void)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&ringbuf_drop_count, &key);

    // ringbuf_drop_count is per-CPU, so each invocation updates only the
    // current CPU's local slot and does not need an atomic increment.
    if (count)
        (*count)++;
}

// Zero fixed-size sample buffers before partial writes. Ringbuf storage is
// reused, so untouched bytes and padding must not leak from a previous sample.
//
// Keep one literal-bound loop per buffer size. A generic memset-style helper
// can be lowered into BPF-unfriendly memset code, while these fixed loops keep
// clang and the verifier on simple bounded stores.
static __always_inline void zero_path_bytes(char *buf)
{
    volatile __u64 *words = (volatile __u64 *)buf;
    volatile const __u64 zero_word = 0;
    for (int i = 0; i < FILE_PATH_LEN / 8; i++)
        words[i] = zero_word;
}

static __always_inline void zero_exec_path_bytes(char *buf)
{
    volatile __u64 *words = (volatile __u64 *)buf;
    volatile const __u64 zero_word = 0;
    for (int i = 0; i < EXEC_PATH_LEN / 8; i++)
        words[i] = zero_word;
}

static __always_inline void zero_argv_blob_bytes(char *buf)
{
    volatile __u64 *words = (volatile __u64 *)buf;
    volatile const __u64 zero_word = 0;
    for (int i = 0; i < ARGV_BLOB_LEN / 8; i++)
        words[i] = zero_word;
}

// Reserve ringbuf storage and fail from the enclosing hook if the buffer is full.
// fail_stmt keeps connect hooks free to return their pass verdict.
#define RESERVE_SAMPLE(var, type, fail_stmt)                        \
    type *var = bpf_ringbuf_reserve(&events, sizeof(*var), 0);      \
    do {                                                            \
        if (!var) {                                                 \
            note_ringbuf_drop();                                    \
            fail_stmt;                                              \
        }                                                           \
    } while (0)

// Common current-task header for samples emitted from current context. Do not
// use this for hooks whose identity comes from a hook argument, such as exec.
#define SET_TASK_HEADER(sample, sample_cgroup_id)                   \
    do {                                                            \
        (sample)->ts_ns = bpf_ktime_get_ns();                       \
        (sample)->cgroup_id = (sample_cgroup_id);                   \
        (sample)->start_boottime = current_start_boottime();        \
        (sample)->tgid = current_tgid();                            \
    } while (0)

static __always_inline __u64 current_start_boottime(void)
{
    // bpf_get_current_task_btf() is available since 5.11; enough for our
    // 5.15+ baseline.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    if (!task)
        return 0;

    // Use the leader's boottime so a worker thread's events resolve to the
    // same (tgid, start_boottime) identity that fork/exec recorded.
    return BPF_CORE_READ(task, group_leader, start_boottime);
}

static __always_inline __s32 current_tgid(void)
{
    return (__s32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u64 current_cgroup_id(void)
{
    // bpf_get_current_cgroup_id() is available since kernel 4.18.
    return bpf_get_current_cgroup_id();
}
