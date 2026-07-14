// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// mount_hooks.bpf.h — mount path exposure attempt observation.

// vmlinux.h does not include UAPI mount macros. Keep these agent-prefixed
// values aligned with Linux include/uapi/linux/mount.h:
// https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/mount.h
#define AGENT_MS_REMOUNT 32
#define AGENT_MS_BIND 4096
#define AGENT_MS_MOVE 8192
#define AGENT_MS_UNBINDABLE (1 << 17)
#define AGENT_MS_PRIVATE (1 << 18)
#define AGENT_MS_SLAVE (1 << 19)
#define AGENT_MS_SHARED (1 << 20)
#define AGENT_MS_PROPAGATION_MASK                                            \
    (AGENT_MS_UNBINDABLE | AGENT_MS_PRIVATE | AGENT_MS_SLAVE | AGENT_MS_SHARED)

static __always_inline void copy_raw_mount_string_to_sample(const char *src,
                                                            char *dst,
                                                            __u16 *offset_out,
                                                            __u8 *truncated_out)
{
    zero_path_bytes(dst);
    if (offset_out)
        *offset_out = 0;
    if (truncated_out)
        *truncated_out = 0;

    if (!src) {
        if (truncated_out)
            *truncated_out = 1;
        return;
    }

    long copied = bpf_probe_read_kernel_str(dst, FILE_PATH_LEN, src);
    if (copied <= 0 && truncated_out) {
        *truncated_out = 1;
        return;
    }
    if (copied == FILE_PATH_LEN && truncated_out)
        *truncated_out = 1;
}

// security_sb_mount observes classic bind and move attempts. dev_name is a
// raw kernel string while target comes from struct path, so the two path
// fields intentionally have different provenance. Other mount operations are
// filtered before reserving a sample.
// Hook signatures are present on the Linux 5.15 baseline:
// https://github.com/torvalds/linux/blob/v5.15/security/security.c#L960-L1008
SEC("fentry/security_sb_mount")
int BPF_PROG(handle_security_sb_mount,
             const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data)
{
    struct path_scratch *scratch;
    struct dentry *target_dentry = NULL;
    __u32 key = 0;
    __u64 cgroup_id = current_cgroup_id();

    (void)type;
    (void)data;

    // Match path_mount() dispatch order so a bind remount or propagation
    // change is not reported as a path exposure attempt:
    // https://github.com/torvalds/linux/blob/v5.15/fs/namespace.c#L3307-L3316
    if (flags & AGENT_MS_REMOUNT)
        return 0;
    if (!(flags & AGENT_MS_BIND) && (flags & AGENT_MS_PROPAGATION_MASK))
        return 0;
    if (!(flags & (AGENT_MS_BIND | AGENT_MS_MOVE)))
        return 0;

    if (!path || !cgroup_is_tracked(cgroup_id))
        return 0;

    scratch = bpf_map_lookup_elem(&path_scratch, &key);
    if (!scratch)
        return 0;

    RESERVE_SAMPLE(sample, struct mount_sample, return 0);

    sample->kind = SAMPLE_KIND_MOUNT;
    sample->source_truncated = 0;
    sample->target_truncated = 0;
    sample->source_offset = 0;
    sample->target_offset = 0;
    sample->_pad_offsets = 0;
    sample->_pad0 = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad1 = 0;

    copy_raw_mount_string_to_sample(dev_name, sample->source_path,
                                    &sample->source_offset,
                                    &sample->source_truncated);
    BPF_CORE_READ_INTO(&target_dentry, path, dentry);
    copy_dentry_fallback_path_to_sample(scratch, sample->target_path,
                                        &sample->target_offset,
                                        &sample->target_truncated,
                                        target_dentry);
    bpf_ringbuf_submit(sample, 0);
    return 0;
}

// security_move_mount is deliberately recorded without classifying whether
// the request attaches or relocates a mount. The hook exposes the resolved
// source and target paths but not enough context to distinguish those cases.
// Linux 5.15 exposes only these two path arguments:
// https://github.com/torvalds/linux/blob/v5.15/include/linux/lsm_hook_defs.h#L83-L84
SEC("fentry/security_move_mount")
int BPF_PROG(handle_security_move_mount,
             const struct path *from_path, const struct path *to_path)
{
    struct path_scratch *scratch;
    struct dentry *source_dentry = NULL;
    struct dentry *target_dentry = NULL;
    __u32 key = 0;
    __u64 cgroup_id = current_cgroup_id();

    if (!from_path || !to_path || !cgroup_is_tracked(cgroup_id))
        return 0;

    scratch = bpf_map_lookup_elem(&path_scratch, &key);
    if (!scratch)
        return 0;

    RESERVE_SAMPLE(sample, struct mount_sample, return 0);

    sample->kind = SAMPLE_KIND_MOUNT;
    sample->source_truncated = 0;
    sample->target_truncated = 0;
    sample->source_offset = 0;
    sample->target_offset = 0;
    sample->_pad_offsets = 0;
    sample->_pad0 = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad1 = 0;

    BPF_CORE_READ_INTO(&source_dentry, from_path, dentry);
    BPF_CORE_READ_INTO(&target_dentry, to_path, dentry);

    copy_dentry_fallback_path_to_sample(scratch, sample->source_path,
                                        &sample->source_offset,
                                        &sample->source_truncated,
                                        source_dentry);
    copy_dentry_fallback_path_to_sample(scratch, sample->target_path,
                                        &sample->target_offset,
                                        &sample->target_truncated,
                                        target_dentry);

    bpf_ringbuf_submit(sample, 0);
    return 0;
}
