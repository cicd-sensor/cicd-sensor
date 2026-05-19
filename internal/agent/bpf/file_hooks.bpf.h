// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// file_hooks.bpf.h — file open and filesystem mutation hooks.

#define OPEN_FLAG_ACCMODE 00000003
#define OPEN_FLAG_RDONLY 00000000
#define OPEN_FLAG_WRONLY 00000001
#define OPEN_FLAG_RDWR 00000002

// Access mode only; status flags like O_APPEND do not grant write permission.
static __always_inline bool file_is_write(__u32 flags)
{
    switch (flags & OPEN_FLAG_ACCMODE) {
    case OPEN_FLAG_WRONLY:
    case OPEN_FLAG_RDWR:
        return true;
    default:
        return false;
    }
}

// Access mode only; special flags are exposed via flags for rule-side checks.
static __always_inline bool file_is_read(__u32 flags)
{
    switch (flags & OPEN_FLAG_ACCMODE) {
    case OPEN_FLAG_RDONLY:
    case OPEN_FLAG_RDWR:
        return true;
    default:
        return false;
    }
}

// security_file_open sees user-visible opens and is allowlisted for bpf_d_path
// on 5.15+. Use fentry instead of lsm/ so hosts do not need lsm=...,bpf.
// dentry_open misses user open(2); it only covers in-kernel opens.
SEC("fentry/security_file_open")
int BPF_PROG(handle_security_file_open, struct file *file)
{
    struct path_scratch *scratch;
    __u64 cgroup_id = current_cgroup_id();
    __u32 flags;

    if (!file || !cgroup_is_tracked(cgroup_id))
        return 0;

    scratch = copy_bpf_d_path_to_scratch(&file->f_path);
    flags = BPF_CORE_READ(file, f_flags);
    RESERVE_SAMPLE(sample, struct file_open_sample, return 0);

    sample->kind = SAMPLE_KIND_FILE_OPEN;
    sample->is_write = 0;
    sample->is_read = 0;
    sample->path_truncated = 0;
    sample->_pad0 = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->flags = flags;
    sample->is_write = file_is_write(flags);
    sample->is_read = file_is_read(flags);

    if (scratch) {
        __builtin_memcpy(sample->path, scratch->buf, sizeof(sample->path));
    } else {
        // Treat unavailable or overlong paths as incomplete, never as exact.
        zero_path_bytes(sample->path);
        sample->path_truncated = 1;
    }

    bpf_ringbuf_submit(sample, 0);
    return 0;
}

// Shared unlink/rmdir submit path; the dentry walk uses per-CPU scratch.
static __always_inline void submit_file_remove(struct dentry *dentry, __u8 is_folder)
{
    struct path_scratch *scratch;
    __u32 key = 0;
    __u64 cgroup_id = current_cgroup_id();

    if (!dentry || !cgroup_is_tracked(cgroup_id))
        return;

    scratch = bpf_map_lookup_elem(&path_scratch, &key);
    if (!scratch)
        return;

    RESERVE_SAMPLE(sample, struct file_remove_sample, return);

    sample->kind = SAMPLE_KIND_FILE_REMOVE;
    sample->is_folder = is_folder;
    sample->path_truncated = 0;
    sample->path_offset = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad = 0;

    copy_dentry_fallback_path_to_sample(scratch, sample->path, &sample->path_offset,
                                        &sample->path_truncated, dentry);

    bpf_ringbuf_submit(sample, 0);
}

// security_path_* would provide parent struct path, but bpf_d_path is not
// allowlisted there on 5.15. Use inode hooks and bounded dentry walk instead.
SEC("fentry/security_inode_unlink")
int BPF_PROG(handle_security_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    (void)dir;
    submit_file_remove(dentry, 0);
    return 0;
}

// Same path tradeoff as unlink; only the sample flag differs.
SEC("fentry/security_inode_rmdir")
int BPF_PROG(handle_security_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
    (void)dir;
    submit_file_remove(dentry, 1);
    return 0;
}

// security_path_rename cannot use bpf_d_path on 5.15, so we walk both dentries
// and expose filesystem-rooted paths rather than mount-resolved paths.
SEC("fentry/security_inode_rename")
int BPF_PROG(handle_security_inode_rename,
             struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry,
             unsigned int flags)
{
    struct path_scratch *scratch;
    __u32 key = 0;
    __u64 cgroup_id = current_cgroup_id();

    (void)old_dir;
    (void)new_dir;
    (void)flags;

    if (!old_dentry || !new_dentry || !cgroup_is_tracked(cgroup_id))
        return 0;

    scratch = bpf_map_lookup_elem(&path_scratch, &key);
    if (!scratch)
        return 0;

    RESERVE_SAMPLE(sample, struct file_move_sample, return 0);

    sample->kind = SAMPLE_KIND_FILE_MOVE;
    sample->from_truncated = 0;
    sample->to_truncated = 0;
    sample->from_offset = 0;
    sample->to_offset = 0;
    sample->_pad0 = 0;
    sample->_pad1 = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad2 = 0;

    // Reuse the per-CPU scratch sequentially: from path first, then to path.
    copy_dentry_fallback_path_to_sample(scratch, sample->from_path, &sample->from_offset,
                                        &sample->from_truncated, old_dentry);
    copy_dentry_fallback_path_to_sample(scratch, sample->to_path, &sample->to_offset,
                                        &sample->to_truncated, new_dentry);

    bpf_ringbuf_submit(sample, 0);
    return 0;
}

// inode_link gives both old and new dentries; dentry walk keeps this usable
// without BPF LSM or path hooks.
SEC("fentry/security_inode_link")
int BPF_PROG(handle_security_inode_link,
             struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry)
{
    struct path_scratch *scratch;
    __u32 key = 0;
    __u64 cgroup_id = current_cgroup_id();

    (void)dir;

    if (!old_dentry || !new_dentry || !cgroup_is_tracked(cgroup_id))
        return 0;

    scratch = bpf_map_lookup_elem(&path_scratch, &key);
    if (!scratch)
        return 0;

    RESERVE_SAMPLE(sample, struct file_link_sample, return 0);

    sample->kind = SAMPLE_KIND_FILE_LINK;
    sample->is_hardlink = 1;
    sample->is_symlink = 0;
    sample->created_truncated = 0;
    sample->existing_truncated = 0;
    sample->created_offset = 0;
    sample->existing_offset = 0;
    sample->_pad0 = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad1 = 0;

    // hardlink: created path is new_dentry, existing path is old_dentry.
    copy_dentry_fallback_path_to_sample(scratch, sample->created_path,
                                        &sample->created_offset,
                                        &sample->created_truncated, new_dentry);
    copy_dentry_fallback_path_to_sample(scratch, sample->existing_path,
                                        &sample->existing_offset,
                                        &sample->existing_truncated, old_dentry);

    bpf_ringbuf_submit(sample, 0);
    return 0;
}

// symlink target is a raw kernel string, so created_path comes from dentry walk
// and existing_path keeps old_name for userspace resolution.
SEC("fentry/security_inode_symlink")
int BPF_PROG(handle_security_inode_symlink,
             struct inode *dir, struct dentry *dentry, const char *old_name)
{
    struct path_scratch *scratch;
    __u32 key = 0;
    __u64 cgroup_id = current_cgroup_id();

    (void)dir;

    if (!dentry || !old_name || !cgroup_is_tracked(cgroup_id))
        return 0;

    scratch = bpf_map_lookup_elem(&path_scratch, &key);
    if (!scratch)
        return 0;

    RESERVE_SAMPLE(sample, struct file_link_sample, return 0);

    sample->kind = SAMPLE_KIND_FILE_LINK;
    sample->is_hardlink = 0;
    sample->is_symlink = 1;
    sample->created_truncated = 0;
    sample->existing_truncated = 0;
    sample->created_offset = 0;
    sample->existing_offset = 0;  // symlink: existing_path is left-aligned
    sample->_pad0 = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad1 = 0;

    // created_path is the symlink dentry itself.
    copy_dentry_fallback_path_to_sample(scratch, sample->created_path,
                                        &sample->created_offset,
                                        &sample->created_truncated, dentry);

    // Keep raw old_name left-aligned; userspace resolves relative targets
    // against dirname(created_path).
    zero_path_bytes(sample->existing_path);
    long n = bpf_probe_read_kernel_str(sample->existing_path,
                                        sizeof(sample->existing_path), old_name);
    if (n <= 0)
        sample->existing_truncated = 1;

    bpf_ringbuf_submit(sample, 0);
    return 0;
}
