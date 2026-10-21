// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// uprobe_mmap receives a completed file-backed VMA. Filtering here keeps
// ordinary data mappings and already-known files out of userspace.
#define HTTP_UPROBE_VM_EXEC 0x4

#include "http_uprobe_identity_helpers.bpf.h"

static __always_inline int emit_http_uprobe_attach_candidate(struct vm_area_struct *vma)
{
    unsigned long vm_flags = 0;
    BPF_CORE_READ_INTO(&vm_flags, vma, vm_flags);
    if (!(vm_flags & HTTP_UPROBE_VM_EXEC))
        return 0;

    struct file *file = BPF_CORE_READ(vma, vm_file);
    if (!file)
        return 0;

    __u64 cgroup_id = current_cgroup_id();
    __u64 root_cgroup_id = http_tracking_root(cgroup_id);
    if (!root_cgroup_id || http_tracking_root(root_cgroup_id) != root_cgroup_id)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    struct super_block *super = BPF_CORE_READ(inode, i_sb);
    if (!super)
        return 0;

    struct file_classification_key classification = {};
    http_uprobe_inode_key(inode, &classification);

    struct http_discovery_key key = {.root_cgroup_id = root_cgroup_id, .file = classification};
    if (bpf_map_lookup_elem(&http_uprobe_discovery_cache, &key))
        return 0;

    __u8 one = 1;
    if (bpf_map_update_elem(&http_uprobe_discovery_cache, &key, &one, BPF_NOEXIST) != 0)
        return 0;

    struct http_uprobe_attach_candidate_sample *sample =
        bpf_ringbuf_reserve(&events, sizeof(*sample), 0);
    if (!sample) {
        // A failed notification must not become a permanent file skip.
        bpf_map_delete_elem(&http_uprobe_discovery_cache, &key);
        note_ringbuf_drop();
        return 0;
    }

    sample->kind = SAMPLE_KIND_HTTP_UPROBE_ATTACH_CANDIDATE;
    sample->tgid = current_tgid();
    sample->cgroup_id = cgroup_id;
    sample->root_cgroup_id = root_cgroup_id;
    sample->vm_start = BPF_CORE_READ(vma, vm_start);
    sample->vm_end = BPF_CORE_READ(vma, vm_end);
    sample->file = classification;
    bpf_ringbuf_submit(sample, 0);
    return 0;
}

SEC("fentry/uprobe_mmap")
int BPF_PROG(handle_uprobe_mmap, struct vm_area_struct *vma)
{
    // A marked Agent thread is querying its temporary read-only mapping.
    // Answer in the same map before VM_EXEC/cgroup gates; no event is emitted.
    __u64 tid = bpf_get_current_pid_tgid();
    struct file_classification_key *request =
        bpf_map_lookup_elem(&http_uprobe_mmap_requests, &tid);
    if (request) {
        if (request->mapped_file.inode)
            return 0; // Preserve the first completed result until userspace reads it.
        struct file *file = BPF_CORE_READ(vma, vm_file);
        struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : 0;
        if (inode) {
            struct file_classification_key result = {};
            http_uprobe_inode_key(inode, &result);
            // If this fails, the empty result makes userspace reject the query.
            if (bpf_map_update_elem(&http_uprobe_mmap_requests, &tid, &result, BPF_EXIST))
                return 0;
        }
        return 0;
    }
    return emit_http_uprobe_attach_candidate(vma);
}
