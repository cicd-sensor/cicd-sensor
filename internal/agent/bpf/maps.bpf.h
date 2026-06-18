// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// maps.bpf.h — BPF maps, globals, and map value types.

// staging_map key size. Must match kernelio.StagingKeyLen.
#define STAGING_KEY_LEN 256
// One dentry component buffer for path fallback: Linux NAME_MAX + NUL.
// Defined here because it sizes path_scratch's tail area.
#define DENTRY_NAME_BUF_LEN 256

// Large BPF buffer zeroing uses literal-bound volatile u64 loops, not
// __builtin_memset. clang can lower large memset to BPF-unsupported libcalls.

// The tail after FILE_PATH_LEN is component scratch plus verifier headroom.
// Only the first FILE_PATH_LEN bytes are copied into ringbuf samples.
struct path_scratch {
    char buf[FILE_PATH_LEN + DENTRY_NAME_BUF_LEN];
};

// The hook only checks staging_map lookup hits; this value is reserved for a
// future kernel path that may surface JobIdentity without userspace lookup.
struct staging_value {
    __u64 job_id_lo;
    __u64 job_id_hi;
};

const volatile struct staging_value *unused_staging_value;

struct {
    // Ringbuf requires 5.8+; our 5.15+ baseline guarantees it.
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // Userspace sets the real cap from node CPU count before load.
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} tracked_cgroups SEC(".maps");

// Per-CPU path workspace. FILE_PATH_LEN does not fit on the 512B BPF stack.
// Call sites still NULL-check lookup results because the verifier requires it.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_scratch);
} path_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_drop_count SEC(".maps");

// staging_map: basename -> staging_value. Userspace stages sibling-container
// basenames; cgroup_mkdir promotes and deletes matching entries in-kernel.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    // Userspace sets the real cap on CollectionSpec before load.
    __uint(max_entries, 1);
    __type(key, char[STAGING_KEY_LEN]);
    __type(value, struct staging_value);
} staging_map SEC(".maps");
