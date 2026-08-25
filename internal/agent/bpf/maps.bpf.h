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

// HTTP/1 parse prefix cap — the number of leading request bytes parsed.
// Defined here because it sizes http_scratch. The prefix stays in this
// per-CPU workspace; only parsed method/path/host are copied into the
// ringbuf sample (redaction invariant).
#define HTTP1_PREFIX_LEN 256
_Static_assert((HTTP1_PREFIX_LEN & (HTTP1_PREFIX_LEN - 1)) == 0,
               "HTTP1_PREFIX_LEN must be a power of two");
_Static_assert(HTTP_PATH_LEN >= HTTP1_PREFIX_LEN &&
               HTTP_HOST_LEN >= HTTP1_PREFIX_LEN,
               "HTTP fields must hold any bounded prefix copy");

// Per-CPU HTTP parse workspace, passed through the tail-call parse pipeline
// (see http_helpers.bpf.h). The raw send prefix stays in this map; only parsed
// method/path/host fields leave the kernel. Each pipeline stage re-reads its
// inputs from here as unknown scalars and re-bounds them.
struct http_scratch {
    char prefix[HTTP1_PREFIX_LEN];   // raw request bytes (never leave kernel)
    __u32 data_len;                  // bytes captured in prefix
    __u32 pos;                       // path start (method_len + 1)
    __u32 mlen;                      // method length (3..7)
    __u32 line_end;                  // request-line space, or data_len
    __u32 path_n;                    // path byte count
    __u32 host_val;                  // host value start
    __u32 host_n;                    // host byte count
    __u32 have_host;                 // 1 = a host value was captured
};

// Tail-call jump table for the HTTP parser. Userspace installs the parse target
// at index 0 before attaching the entry program.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} http_stages SEC(".maps");

// Separate jump table for the OpenSSL uprobe HTTP parser
// (http_uprobe_hooks.bpf.h). It
// needs its own PROG_ARRAY because a uprobe program is kprobe-type and a tail
// call cannot cross program types, so the fentry-type http_stages target above
// is not reusable. The parse target shares the same http_scratch and the same
// http_step_* helpers; only the entry program type and the source tag differ.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} http_tls_stages SEC(".maps");

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
    __type(value, struct http_scratch);
} http_scratch SEC(".maps");

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
