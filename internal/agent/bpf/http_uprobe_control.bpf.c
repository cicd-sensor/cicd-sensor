//go:build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "include/vmlinux/vmlinux.h"
#include "include/libbpf/bpf_core_read.h"
#include "include/libbpf/bpf_helpers.h"
#include "include/libbpf/bpf_tracing.h"
#include "kernel_samples.h"
#include "http_uprobe_control_maps.bpf.h"
#include "http_uprobe_identity_helpers.bpf.h"

// Optional internal hooks are loaded separately: an absent attach point must
// not break the base sensor. Maps are replacements from the primary object.
// Linux references (these internal attach points are feature-probed):
// https://github.com/torvalds/linux/blob/v6.8/kernel/events/uprobes.c#L1117
// https://github.com/torvalds/linux/blob/v6.8/fs/proc/task_mmu.c#L246
// No kernel pointers leave these maps. VMA backing is necessary after copy-up;
// reopening map_files would observe the currently selected backing instead.
// Fixed-size results and bounded maps use 5.15 helpers/CO-RE, no kfunc/loops.
SEC("fentry/uprobe_register")
int BPF_PROG(handle_http_uprobe_register, struct inode *inode, loff_t offset,
             struct uprobe_consumer *consumer)
{
    (void)consumer;
    __u64 tid = bpf_get_current_pid_tgid();
    struct http_uprobe_control_request *request =
        bpf_map_lookup_elem(&http_uprobe_control_requests, &tid);
    if (!request || request->operation != HTTP_UPROBE_CONTROL_REGISTER || !inode)
        return 0;
    __u64 zero = 0;
    struct http_uprobe_control_result result = {.nonce = request->nonce, .start = offset};
    http_uprobe_inode_key(inode, &result.file);
    if (!bpf_map_update_elem(&http_uprobe_control_results, &zero, &result, BPF_ANY))
        bpf_map_delete_elem(&http_uprobe_control_requests, &tid);
    return 0;
}

SEC("fentry/show_map_vma")
int BPF_PROG(handle_http_uprobe_map_vma, struct seq_file *seq, struct vm_area_struct *vma)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct http_uprobe_control_request *request =
        bpf_map_lookup_elem(&http_uprobe_control_requests, &tid);
    if (!request || request->operation != HTTP_UPROBE_CONTROL_SCAN)
        return 0;
    struct proc_maps_private *private = BPF_CORE_READ(seq, private);
    struct task_struct *task = private ? BPF_CORE_READ(private, task) : 0;
    if (!task || BPF_CORE_READ(task, tgid) != request->pid)
        return 0;
    struct file *file = BPF_CORE_READ(vma, vm_file);
    struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : 0;
    // vm_flags is const in newer vmlinux headers. Use an initialized mutable
    // destination rather than BPF_CORE_READ's typeof temporary (clang 22).
    unsigned long flags = 0;
    if (!inode || BPF_CORE_READ_INTO(&flags, vma, vm_flags) || !(flags & 0x4))
        return 0;
    struct http_uprobe_control_result result = {
        .nonce = request->nonce,
        .start = BPF_CORE_READ(vma, vm_start),
        .end = BPF_CORE_READ(vma, vm_end),
    };
    http_uprobe_inode_key(inode, &result.file);
    __u64 start = result.start;
    if (bpf_map_update_elem(&http_uprobe_control_results, &start, &result, BPF_ANY))
        request->overflow = 1;
    request->count++;
    return 0;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
