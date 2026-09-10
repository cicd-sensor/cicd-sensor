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
    __u64 owner = http_tracking_owner(cgroup_id);
    if (!owner)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    struct super_block *super = BPF_CORE_READ(inode, i_sb);
    if (!super)
        return 0;

    // Kernel dev_t stores the major above its 20-bit minor field.
    __u32 device = BPF_CORE_READ(super, s_dev);
    struct file_classification_key classification = {
        .mapped_file = {
            .device_major = device >> 20,
            .device_minor = device & ((1U << 20) - 1),
            .inode = BPF_CORE_READ(inode, i_ino),
        },
    };
    http_uprobe_inode_ctime(inode, &classification);

    struct http_discovery_key key = {.owner = owner, .file = classification};
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
    sample->owner = owner;
    sample->vm_start = BPF_CORE_READ(vma, vm_start);
    sample->vm_end = BPF_CORE_READ(vma, vm_end);
    sample->file = classification;
    bpf_ringbuf_submit(sample, 0);
    return 0;
}

SEC("fentry/uprobe_mmap")
int BPF_PROG(handle_uprobe_mmap, struct vm_area_struct *vma)
{
    // A worker-owned request identifies its own temporary PROT_READ mapping.
    // This branch must precede VM_EXEC/cgroup gates, and emits no event.
    __u64 tid = bpf_get_current_pid_tgid();
    struct http_uprobe_control_request *request =
        bpf_map_lookup_elem(&http_uprobe_control_requests, &tid);
    if (request) {
        struct file *file = BPF_CORE_READ(vma, vm_file);
        struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : 0;
        if (inode) {
            __u64 zero = 0;
            struct http_uprobe_control_result result = {
                .nonce = request->nonce,
            };
            http_uprobe_inode_key(inode, &result.file);
            if (!bpf_map_update_elem(&http_uprobe_control_results, &zero, &result, BPF_ANY))
                bpf_map_delete_elem(&http_uprobe_control_requests, &tid);
        }
        return 0;
    }
    return emit_http_uprobe_attach_candidate(vma);
}
