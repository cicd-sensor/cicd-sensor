// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// cgroup_hooks.bpf.h — cgroup lifecycle hooks and staging promotion.

// Promote a staged basename into tracked_cgroups. We read kernfs_node->name
// instead of parsing the full tracepoint path; the old full-path parser pushed
// handle_cgroup_mkdir over the 5.15 verifier's 1M instruction budget.
static __always_inline bool match_staging_and_track_cgroup(struct cgroup *cgrp, __u64 cgroup_id)
{
    char key[STAGING_KEY_LEN] = {};
    const char *name;

    // kn->name is the cgroup directory basename, matching staging_map keys.
    name = BPF_CORE_READ(cgrp, kn, name);
    if (!name)
        return false;

    long n = bpf_probe_read_kernel_str(key, sizeof(key), name);
    if (n <= 1)
        return false;

    struct staging_value *val = bpf_map_lookup_elem(&staging_map, key);
    if (!val)
        return false;

    // Make the kernel map reflect ownership before userspace mirrors it.
    __u8 one = 1;
    if (bpf_map_update_elem(&tracked_cgroups, &cgroup_id, &one, BPF_ANY) != 0)
        return false;

    bpf_map_delete_elem(&staging_map, key);
    return true;
}

SEC("tp_btf/cgroup_mkdir")
int BPF_PROG(handle_cgroup_mkdir, struct cgroup *cgrp, const char *path)
{
    __u64 cgroup_id = cgroup_id_from_cgroup(cgrp);
    __u64 parent_cgroup_id = parent_cgroup_id_from_cgroup(cgrp);
    __u8 staging_matched = 0;
    __u8 one = 1;

    if (cgroup_is_tracked(parent_cgroup_id)) {
        // Track child cgroups before userspace observes the mkdir.
        if (bpf_map_update_elem(&tracked_cgroups, &cgroup_id, &one, BPF_ANY) != 0)
            return 0;
    } else {
        // Sibling-container fallback: an untracked parent may have a staged child basename.
        if (!match_staging_and_track_cgroup(cgrp, cgroup_id))
            return 0;
        staging_matched = 1;
    }

    RESERVE_SAMPLE(sample, struct cgroup_mkdir_sample, return 0);

    sample->kind = SAMPLE_KIND_CGROUP_MKDIR;
    sample->staging_matched = staging_matched;
    sample->_pad0 = 0;
    sample->_pad1 = 0;
    sample->cgroup_id = cgroup_id;
    sample->parent_cgroup_id = parent_cgroup_id;
    sample->ts_ns = bpf_ktime_get_ns();
    sample->path[0] = '\0';
    if (path)
        bpf_probe_read_kernel_str(sample->path, sizeof(sample->path), path);

    bpf_ringbuf_submit(sample, 0);
    return 0;
}

// handle_cgroup_attach_task captures the source cgroup before the kernel
// overwrites it, then extends tracking for the destination cgroup.
SEC("fentry/cgroup_attach_task")
int BPF_PROG(handle_cgroup_attach_task, struct cgroup *dst_cgrp, struct task_struct *leader, bool threadgroup)
{
    struct cgroup *old_cgrp;
    __u64 source_cgroup_id;
    __u64 destination_cgroup_id;
    __u8 *source_tracked;
    __u8 *destination_tracked;

    (void)threadgroup;

    if (!dst_cgrp || !leader)
        return 0;

    // At fentry time, leader still points at the source cgroup. Filter on
    // source first so the common untracked-source path exits before we read
    // dst_cgrp.
    old_cgrp = BPF_CORE_READ(leader, cgroups, dfl_cgrp);
    source_cgroup_id = cgroup_id_from_cgroup(old_cgrp);
    source_tracked = bpf_map_lookup_elem(&tracked_cgroups, &source_cgroup_id);
    if (!source_tracked)
        return 0;

    destination_cgroup_id = cgroup_id_from_cgroup(dst_cgrp);
    destination_tracked = bpf_map_lookup_elem(&tracked_cgroups, &destination_cgroup_id);

    // Track the destination before later samples hit cgroup_is_tracked().
    if (!destination_tracked) {
        __u8 one = 1;
        if (bpf_map_update_elem(&tracked_cgroups, &destination_cgroup_id, &one, BPF_ANY) != 0)
            return 0;
    }

    RESERVE_SAMPLE(sample, struct cgroup_attach_sample, return 0);

    sample->kind = SAMPLE_KIND_CGROUP_ATTACH;
    sample->_pad = 0;
    sample->ts_ns = bpf_ktime_get_ns();
    sample->source_cgroup_id = source_cgroup_id;
    sample->destination_cgroup_id = destination_cgroup_id;
    sample->tgid = BPF_CORE_READ(leader, tgid);
    sample->_pad2 = 0;

    bpf_ringbuf_submit(sample, 0);
    return 0;
}

SEC("tp_btf/cgroup_rmdir")
int BPF_PROG(handle_cgroup_rmdir, struct cgroup *cgrp, const char *path)
{
    __u64 cgroup_id;

    (void)path;

    cgroup_id = cgroup_id_from_cgroup(cgrp);
    if (!cgroup_is_tracked(cgroup_id))
        return 0;

    RESERVE_SAMPLE(sample, struct cgroup_rmdir_sample, return 0);

    sample->kind = SAMPLE_KIND_CGROUP_RMDIR;
    sample->_pad = 0;
    sample->cgroup_id = cgroup_id;
    sample->ts_ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(sample, 0);
    return 0;
}
