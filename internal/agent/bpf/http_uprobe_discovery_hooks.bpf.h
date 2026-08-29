// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// uprobe_mmap receives a completed file-backed VMA. Filtering here keeps
// ordinary data mappings and already-known files out of userspace.
#define HTTP_UPROBE_VM_EXEC 0x4
#define HTTP_UPROBE_SIGSTOP 19

// CO-RE flavor structs expose inode ctime layouts used before Linux 6.12.
struct inode___http_uprobe_legacy {
    struct timespec64 i_ctime;
} __attribute__((preserve_access_index));

struct inode___http_uprobe_middle {
    struct timespec64 __i_ctime;
} __attribute__((preserve_access_index));

static __always_inline void http_uprobe_inode_ctime(
    struct inode *inode,
    struct file_classification_key *key)
{
    if (bpf_core_field_exists(inode->i_ctime_sec)) {
        key->ctime_sec = BPF_CORE_READ(inode, i_ctime_sec);
        // Newer kernels reserve bit 31 as I_CTIME_QUERIED. stat(2) masks it,
        // so remove the kernel-only flag before userspace verifies this key.
        key->ctime_nsec = BPF_CORE_READ(inode, i_ctime_nsec) & 0x7fffffffU;
        return;
    }

    if (bpf_core_field_exists(((struct inode___http_uprobe_middle *)0)->__i_ctime)) {
        struct inode___http_uprobe_middle *middle =
            (struct inode___http_uprobe_middle *)inode;

        key->ctime_sec = BPF_CORE_READ(middle, __i_ctime.tv_sec);
        key->ctime_nsec = BPF_CORE_READ(middle, __i_ctime.tv_nsec);
        return;
    }

    struct inode___http_uprobe_legacy *legacy =
        (struct inode___http_uprobe_legacy *)inode;
    key->ctime_sec = BPF_CORE_READ(legacy, i_ctime.tv_sec);
    key->ctime_nsec = BPF_CORE_READ(legacy, i_ctime.tv_nsec);
}

// http_uprobe_request_process_stop creates at most one recovery lease for a
// process generation. Another mapping reuses the existing lease timestamp and
// does not send another SIGSTOP. The return value is 1 only when this call
// successfully requested the stop.
static __always_inline __u8 http_uprobe_request_process_stop(
    const struct http_uprobe_stop_lease_key *lease_key,
    __u64 *stop_started_ns)
{
    __u64 stopped_at_ns = bpf_ktime_get_ns();
    // BPF_NOEXIST atomically selects one mapping as the stop owner.
    if (bpf_map_update_elem(
            &http_uprobe_stop_leases,
            lease_key,
            &stopped_at_ns,
            BPF_NOEXIST) != 0) {
        __u64 *existing_stop_started_ns =
            bpf_map_lookup_elem(&http_uprobe_stop_leases, lease_key);
        if (!existing_stop_started_ns)
            return 0;

        *stop_started_ns = *existing_stop_started_ns;
        // The existing lease owns the SIGSTOP; this mapping did not request
        // another stop and only reuses the original stop timestamp.
        return 0;
    }

    if (bpf_send_signal(HTTP_UPROBE_SIGSTOP) != 0) {
        // No stop was established, so there is nothing to recover after a
        // crash. Classification still proceeds without the first-call guard.
        bpf_map_delete_elem(&http_uprobe_stop_leases, lease_key);
        return 0;
    }

    *stop_started_ns = stopped_at_ns;
    return 1;
}

// For the first executable mapping of a file in a tracked cgroup, claim the
// file for classification, request one bounded process stop, and notify the
// userspace worker. The order is safety-critical: reserve the notification
// before SIGSTOP, and keep the cache pending until userspace resolves it.
static __always_inline int emit_http_uprobe_attach_candidate(struct vm_area_struct *vma)
{
    __u64 cgroup_id = current_cgroup_id();
    if (!cgroup_is_tracked(cgroup_id))
        return 0;

    unsigned long vm_flags = 0;
    BPF_CORE_READ_INTO(&vm_flags, vma, vm_flags);
    if (!(vm_flags & HTTP_UPROBE_VM_EXEC))
        return 0;

    struct file *file = BPF_CORE_READ(vma, vm_file);
    if (!file)
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

    // The cache suppresses repeat notifications for the same file. Userspace
    // changes this pending entry to resolved after classification and attach.
    if (bpf_map_lookup_elem(&http_uprobe_discovery_cache, &classification))
        return 0;

    __u8 pending_state = HTTP_UPROBE_DISCOVERY_PENDING;
    if (bpf_map_update_elem(&http_uprobe_discovery_cache, &classification, &pending_state, BPF_NOEXIST) != 0)
        return 0;

    struct http_uprobe_stop_lease_key lease_key = {
        .tgid = current_tgid(),
        .start_boottime = current_start_boottime(),
    };
    if (lease_key.start_boottime == 0) {
        bpf_map_delete_elem(&http_uprobe_discovery_cache, &classification);
        return 0;
    }

    // Reserve before SIGSTOP: a full ring buffer returns without stopping.
    // Every successful stop therefore has a notification slot and recovery lease.
    struct http_uprobe_attach_candidate_sample *sample =
        bpf_ringbuf_reserve(&http_uprobe_attach_candidates, sizeof(*sample), 0);
    if (!sample) {
        // A failed notification must not become a permanent file skip.
        bpf_map_delete_elem(&http_uprobe_discovery_cache, &classification);
        note_ringbuf_drop();
        return 0;
    }

    __u64 stop_started_ns = 0;
    __u8 stop_requested =
        http_uprobe_request_process_stop(&lease_key, &stop_started_ns);

    // Emit only identities and stop metadata. ELF bytes remain in the mapped
    // file and HTTP bytes never enter this control-plane sample.
    sample->kind = SAMPLE_KIND_HTTP_UPROBE_ATTACH_CANDIDATE;
    sample->tgid = lease_key.tgid;
    sample->start_boottime = lease_key.start_boottime;
    sample->stop_started_ns = stop_started_ns;
    sample->vm_start = BPF_CORE_READ(vma, vm_start);
    sample->vm_end = BPF_CORE_READ(vma, vm_end);
    sample->file = classification;
    sample->stop_requested = stop_requested;
    __builtin_memset(sample->_pad, 0, sizeof(sample->_pad));

    bpf_ringbuf_submit(sample, 0);
    return 0;
}

SEC("fentry/uprobe_mmap")
int BPF_PROG(handle_uprobe_mmap, struct vm_area_struct *vma)
{
    return emit_http_uprobe_attach_candidate(vma);
}
