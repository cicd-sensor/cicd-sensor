// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// kernel_samples.h — ringbuf sample ABI shared with bpf2go and Go decoders.
//
// This header owns sample kind values, sample field-size constants, and
// struct layouts. Hook logic, helper limits, and map-only values belong in
// their domain headers.
//
// ABI rules:
//   - every *_sample starts with __u32 kind at byte offset 0;
//   - SAMPLE_KIND_* values must match kernelio.SampleKind* exactly;
//   - struct field order / padding is checked by bpf2go decoder tests.
enum agent_sample_kind {
    SAMPLE_KIND_FORK = 1,
    SAMPLE_KIND_CGROUP_MKDIR = 2,
    SAMPLE_KIND_CGROUP_ATTACH = 3,
    SAMPLE_KIND_CGROUP_RMDIR = 4,
    SAMPLE_KIND_EXEC = 5,
    SAMPLE_KIND_NETWORK_CONNECT_V4 = 6,
    SAMPLE_KIND_NETWORK_CONNECT_V6 = 7,
    SAMPLE_KIND_FILE_OPEN = 8,
    SAMPLE_KIND_FILE_REMOVE = 9,
    SAMPLE_KIND_FILE_MOVE = 10,
    SAMPLE_KIND_FILE_LINK = 11,
    SAMPLE_KIND_DNS = 12,
    SAMPLE_KIND_UNIX_SOCKET_CONNECT = 13,
};

// Field-size constants below define generated Go struct layout.
// Keep them here even when a hook helper also needs the same capacity.

// Linux ABI: sizeof(sockaddr_un.sun_path) == 108.
#define UNIX_SOCKET_SUN_PATH_LEN 108
#define CGROUP_PATH_LEN 512
// FILE_PATH_LEN is below Linux PATH_MAX (4096) to keep ringbuf samples small.
// Overlong or unavailable paths set *_truncated so userspace will not treat
// the captured path as complete.
#define FILE_PATH_LEN 1024
#define EXEC_PATH_LEN 512
#define ARGV_BLOB_LEN 2048
// DNS stores a prefix, not a full packet. The first question fits in this cap.
#define DNS_PAYLOAD_LEN 512

// These capacities are used with masked indexes / fixed-size loops.
_Static_assert((DNS_PAYLOAD_LEN & (DNS_PAYLOAD_LEN - 1)) == 0,
               "DNS_PAYLOAD_LEN must be a power of two");
_Static_assert((ARGV_BLOB_LEN & (ARGV_BLOB_LEN - 1)) == 0,
               "ARGV_BLOB_LEN must be a power of two");
_Static_assert((FILE_PATH_LEN & (FILE_PATH_LEN - 1)) == 0,
               "FILE_PATH_LEN must be a power of two");

struct fork_sample {
    __u32 kind;
    __u32 _pad;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 child_start_boottime;
    __u64 parent_start_boottime;
    __s32 child_tgid;
    __s32 parent_tgid;
};

struct cgroup_mkdir_sample {
    __u32 kind;
    // 1 when mkdir promoted a staged basename into tracked_cgroups.
    __u8 staging_matched;
    __u8 _pad0;
    __u16 _pad1;
    __u64 cgroup_id;
    __u64 parent_cgroup_id;
    __u64 ts_ns;
    char path[CGROUP_PATH_LEN];
};

struct cgroup_attach_sample {
    __u32 kind;
    __u32 _pad;
    __u64 ts_ns;
    __u64 source_cgroup_id;
    __u64 destination_cgroup_id;
    __s32 tgid;
    __u32 _pad2;
};

struct cgroup_rmdir_sample {
    __u32 kind;
    __u32 _pad;
    __u64 cgroup_id;
    __u64 ts_ns;
};

struct exec_sample {
    __u32 kind;
    __u8 argv_truncated;
    __u8 argv_faulted;
    __u16 _pad0;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 start_boottime;
    __s32 tgid;
    // 1 only for shmem/tmpfs-backed executables named with the memfd: prefix.
    __u8 is_memfd;
    __u8 _pad2[3];
    __u32 argc;
    __u32 argv_blob_len;
    char exec_path[EXEC_PATH_LEN];
    char argv_blob[ARGV_BLOB_LEN];
};

struct file_open_sample {
    __u32 kind;
    __u8 is_write;
    __u8 is_read;
    __u8 path_truncated;
    __u8 _pad0;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 start_boottime;
    __s32 tgid;
    __u32 flags;
    char path[FILE_PATH_LEN];
};

// file_remove_sample / file_move_sample / file_link_sample use dentry fallback
// paths: paths are right-aligned and *_offset marks the start byte.
struct file_remove_sample {
    __u32 kind;
    __u8 is_folder;        // 1 = security_inode_rmdir, 0 = security_inode_unlink
    __u8 path_truncated;   // 1 = walk hit its depth bound or buffer underflow
    __u16 path_offset;     // start of the right-aligned path within path[]
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 start_boottime;
    __s32 tgid;
    __u32 _pad;
    char path[FILE_PATH_LEN];
};

struct file_move_sample {
    __u32 kind;
    __u8 from_truncated;
    __u8 to_truncated;
    __u16 from_offset;
    __u16 to_offset;
    __u16 _pad0;
    __u32 _pad1;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 start_boottime;
    __s32 tgid;
    __u32 _pad2;
    char from_path[FILE_PATH_LEN];
    char to_path[FILE_PATH_LEN];
};

struct file_link_sample {
    __u32 kind;
    __u8 is_hardlink;
    __u8 is_symlink;
    __u8 created_truncated;
    __u8 existing_truncated;
    __u16 created_offset;
    // Symlink old_name is a raw target string, often relative, not a dentry.
    // Store it left-aligned with offset 0; userspace resolves it from created_path.
    __u16 existing_offset;
    __u32 _pad0;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 start_boottime;
    __s32 tgid;
    __u32 _pad1;
    char created_path[FILE_PATH_LEN];
    char existing_path[FILE_PATH_LEN];
};

struct net_v4_sample {
    __u32 kind;
    __u8 protocol;
    __u8 blocked;
    __u16 _pad0;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 start_boottime;
    __s32 tgid;
    __u32 _pad1;
    __u8 remote_ip[4];
    __u16 remote_port;
    __u16 _pad2;
};

struct net_v6_sample {
    __u32 kind;
    __u8 protocol;
    __u8 blocked;
    __u16 _pad0;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 start_boottime;
    __s32 tgid;
    __u32 _pad1;
    __u8 remote_ip[16];
    __u16 remote_port;
    __u16 _pad2;
};

// AF_UNIX connect sample. The unix_{stream,dgram}_connect fentry programs
// fire pre-namei, so userspace combines relative sun_path with cwd[] when
// cwd is available.
struct unix_socket_connect_sample {
    __u32 kind;
    __u32 sun_path_len;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 start_boottime;
    __s32 tgid;
    __u8 socket_type;
    __u8 is_abstract;
    __u8 sun_path_truncated;
    __u8 cwd_truncated;
    __u8 cwd_unavailable;
    __u8 _pad0;
    __u16 cwd_offset;
    __u8 sun_path[UNIX_SOCKET_SUN_PATH_LEN];
    char cwd[FILE_PATH_LEN];
};

// DNS sendmsg sample. payload[] is a best-effort prefix; domain extraction
// only needs the first question, so no truncation flag is exposed.
struct dns_sample {
    __u32 kind;
    __u8 source;
    __u8 family;
    __u16 _pad0;
    __u16 dport;
    __u16 _pad1;
    __u32 payload_len;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 start_boottime;
    __s32 tgid;
    __u32 _pad2;
    __u8 daddr_v4[4];
    __u8 daddr_v6[16];
    __u8 payload[DNS_PAYLOAD_LEN];
};

/* Force BTF emission for bpf2go. */
const volatile struct fork_sample *unused_fork_sample;
const volatile struct cgroup_mkdir_sample *unused_cgroup_mkdir_sample;
const volatile struct cgroup_attach_sample *unused_cgroup_attach_sample;
const volatile struct cgroup_rmdir_sample *unused_cgroup_rmdir_sample;
const volatile struct exec_sample *unused_exec_sample;
const volatile struct file_open_sample *unused_file_open_sample;
const volatile struct file_remove_sample *unused_file_remove_sample;
const volatile struct file_move_sample *unused_file_move_sample;
const volatile struct file_link_sample *unused_file_link_sample;
const volatile struct net_v4_sample *unused_net_v4_sample;
const volatile struct net_v6_sample *unused_net_v6_sample;
const volatile struct dns_sample *unused_dns_sample;
const volatile struct unix_socket_connect_sample *unused_unix_socket_connect_sample;
