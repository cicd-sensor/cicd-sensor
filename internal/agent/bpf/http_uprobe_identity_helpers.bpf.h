// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

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

// Both discovery and control requests use the backing file's kernel dev_t.
static __always_inline void http_uprobe_inode_key(struct inode *inode,
                                                 struct file_classification_key *key)
{
    // Kernel dev_t stores the major above its 20-bit minor field.
    __u32 device = BPF_CORE_READ(inode, i_sb, s_dev);
    key->mapped_file.device_major = device >> 20;
    key->mapped_file.device_minor = device & ((1U << 20) - 1);
    key->mapped_file.inode = BPF_CORE_READ(inode, i_ino);
    http_uprobe_inode_ctime(inode, key);
}
