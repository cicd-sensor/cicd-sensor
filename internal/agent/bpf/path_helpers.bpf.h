// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// path_helpers.bpf.h — bounded kernel path resolution.

// Fixed dentry-walk bound: enough for CI paths, small enough for 5.15.
#define DENTRY_WALK_DEPTH 64

// Use bpf_d_path when the hook is allowlisted for it. This gives a
// mount-aware path, unlike the dentry-walk fallback below.
static __always_inline struct path_scratch *copy_bpf_d_path_to_scratch(struct path *path)
{
    struct path_scratch *scratch;
    __u32 key = 0;
    long written;

    if (!path)
        return NULL;

    scratch = bpf_map_lookup_elem(&path_scratch, &key);
    if (!scratch)
        return NULL;

    // security_file_open is allowlisted on 5.15+. Clear the per-CPU scratch
    // first; it may carry bytes from another task.
    zero_path_bytes(scratch->buf);
    written = bpf_d_path(path, scratch->buf, FILE_PATH_LEN);
    if (written <= 0)
        return NULL;

    return scratch;
}

// Resolve a dentry path fallback for inode hooks where bpf_d_path is not
// allowlisted on 5.15. It follows d_parent links and prepends each component
// into scratch->buf, so the result is filesystem-rooted, not mount/bind aware.
//
// Returns 0 on full resolution, 1 when truncated (depth cap, buffer
// underflow, or per-name read failure), -1 when scratch / dentry are unusable.
//
// __noinline (not __always_inline): hooks that walk two dentries
// (rename / link / symlink) would otherwise embed the unrolled body twice.
// BPF-to-BPF call is available since 4.16 and keeps the 5.15 verifier budget
// manageable.
static __noinline int resolve_dentry_fallback_path_to_scratch(
        struct dentry *dentry,
        struct path_scratch *scratch,
        __u16 *offset_out)
{
    if (!scratch || !dentry)
        return -1;

    // scratch->buf layout:
    //   [0, FILE_PATH_LEN)                         final path buffer
    //   [FILE_PATH_LEN, FILE_PATH_LEN+DENTRY_NAME_BUF_LEN) component temp
    char *path_buf = scratch->buf;
    char *component_tmp = &scratch->buf[FILE_PATH_LEN];

    zero_path_bytes(path_buf);

    // Build from the end of the buffer backwards; FILE_PATH_LEN-1 means empty.
    int offset = FILE_PATH_LEN - 1;

    bool truncated = false;
    bool reached_root = false;

    // Use `continue` (not `break`) for the early-exit guard: unroll(full)
    // refuses to fully unroll a body containing reachable breaks, and
    // -Werror escalates the warning to a build failure.
    #pragma clang loop unroll(full)
    for (int depth = 0; depth < DENTRY_WALK_DEPTH; depth++) {
        if (reached_root || truncated)
            continue;

        // NULL parent would otherwise look like root in the pointer check.
        if (!dentry) {
            truncated = true;
            continue;
        }

        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        bool is_root = (dentry == parent);

        if (is_root) {
            // No component is prepended for root, so root alone needs "/".
            if (offset == FILE_PATH_LEN - 1 && offset > 0) {
                offset--;
                path_buf[offset & (FILE_PATH_LEN - 1)] = '/';
            }
            reached_root = true;
            continue;
        }

        const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
        if (!name_ptr) {
            dentry = parent;
            continue;
        }

        // The scratch buffer is split into final path bytes plus one
        // component-sized temp area. _str writes NUL, so read into temp first
        // and copy only the component bytes into the final path.
        long copied = bpf_probe_read_kernel_str(component_tmp, DENTRY_NAME_BUF_LEN, name_ptr);
        if (copied < 0) {
            // Avoid emitting a silently incomplete component.
            truncated = true;
            continue;
        }
        if (copied <= 1) {
            // Empty name: keep walking the parent.
            dentry = parent;
            continue;
        }

        unsigned int namelen = (unsigned int)(copied - 1);  // strip NUL
        if (namelen >= DENTRY_NAME_BUF_LEN)
            namelen = DENTRY_NAME_BUF_LEN - 1;

        // Prepend "/name" before the path already assembled to the right.
        if (offset < (int)(namelen + 1)) {
            truncated = true;
            continue;
        }

        offset -= (int)(namelen + 1);

        // Mask so the verifier sees bounded writes into the power-of-two buf.
        __u32 sep_idx = (__u32)offset & (FILE_PATH_LEN - 1);
        path_buf[sep_idx] = '/';

        __u32 dst_off = (__u32)(offset + 1) & (FILE_PATH_LEN - 1);
        // Map-value copy; scratch padding gives verifier headroom.
        (void)bpf_probe_read_kernel(&path_buf[dst_off], namelen, component_tmp);

        dentry = parent;
    }

    // Never let userspace treat a partial path as exact.
    if (!reached_root)
        truncated = true;

    if (offset < 0)
        offset = 0;
    if (offset > FILE_PATH_LEN - 1)
        offset = FILE_PATH_LEN - 1;

    if (offset_out)
        *offset_out = (__u16)offset;

    return truncated ? 1 : 0;
}

// Copy the dentry-walk result into the sample. The fixed-size memcpy avoids
// dynamic range proofs and excludes scratch padding.
static __always_inline void copy_dentry_fallback_path_to_sample(
        struct path_scratch *scratch,
        char *dst,
        __u16 *offset_out,
        __u8 *truncated_out,
        struct dentry *dentry)
{
    __u16 off = 0;
    int rc = resolve_dentry_fallback_path_to_scratch(dentry, scratch, &off);
    if (rc < 0) {
        // Failed path capture becomes "" at offset 0. truncated also means
        // "path unavailable", not only "path too long".
        if (dst)
            dst[0] = '\0';
        if (offset_out)
            *offset_out = 0;
        if (truncated_out)
            *truncated_out = 1;
        return;
    }

    __builtin_memcpy(dst, scratch->buf, FILE_PATH_LEN);
    if (offset_out)
        *offset_out = off;
    if (truncated_out)
        *truncated_out = (__u8)(rc == 1 ? 1 : 0);
}

// UNIX socket paths can be relative; capture cwd so userspace can interpret
// sun_path without relying on /proc after the task moves on.
static __always_inline bool copy_current_cwd_fallback_path_to_sample(
        struct unix_socket_connect_sample *sample)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return false;
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    if (!fs)
        return false;
    struct dentry *cwd_dentry = BPF_CORE_READ(fs, pwd.dentry);
    if (!cwd_dentry)
        return false;
    __u32 scratch_key = 0;
    struct path_scratch *scratch = bpf_map_lookup_elem(&path_scratch, &scratch_key);
    if (!scratch)
        return false;
    copy_dentry_fallback_path_to_sample(scratch, sample->cwd,
                                        &sample->cwd_offset,
                                        &sample->cwd_truncated,
                                        cwd_dentry);
    return true;
}
