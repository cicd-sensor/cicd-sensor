// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// http_hooks.bpf.h — cleartext HTTP request-line capture.
//
// The parse is NOT one program — it is a tail-call pipeline (see
// http_helpers.bpf.h and the design doc). The entry program below is the only
// one attached to tcp_sendmsg; the six stage programs are installed in the
// http_stages PROG_ARRAY by userspace and reached via bpf_tail_call. Each
// stage runs with fresh verifier state, which is what makes the whole parse
// loadable on Linux 5.15 / 6.6 / 6.18 — a single monolithic program could not
// be. Path/host are copied into per-CPU staging fields by their own stages
// because 6.6 rejects a variable-length read into the ringbuf sample; the
// emit stage then does a fixed-size memcpy out.
//
//   kernel: tcp_sendmsg
//      |  (only this program is attached)
//      v
//   entry ─── cgroup gate → capture ≤256B prefix → parse request line
//      |
//      |  bpf_tail_call(http_stages[i]); each arrow below is one tail call,
//      v  and a stage that returns without tail-calling drops the capture.
//   [0] pathlen    scan to '?' / request-line space → path length
//   [1] pathcopy   stage path bytes into scratch->path
//   [2] hostfind   scan headers for "\r\nHost:" → host value start
//   [3] hostlen    find the CR/LF terminator → host length (or empty)
//   [4] hostcopy   stage host bytes into scratch->host
//   [5] emit       reserve ringbuf sample, fixed-size copy in, submit
//
// All stages share the per-CPU http_scratch workspace (same CPU across the
// chain), and every stage runs at most one break-scan over the prefix. All
// seven programs carry the same SEC("fentry/tcp_sendmsg") and signature not
// because they all hook tcp_sendmsg, but because bpf_tail_call requires the
// caller and target to share program type, attach target, and signature.

// Stage indices in the http_stages jump table.
#define HTTP_STAGE_PATHLEN  0
#define HTTP_STAGE_PATHCOPY 1
#define HTTP_STAGE_HOSTFIND 2
#define HTTP_STAGE_HOSTLEN  3
#define HTTP_STAGE_HOSTCOPY 4
#define HTTP_STAGE_EMIT     5

// Entry: content detection separates cleartext from ciphertext (a TLS write
// starts with a record byte and never matches a method token; KTLS plaintext
// is intercepted before tcp_sendmsg). On a match it copies the prefix into the
// scratch map and parses the request line (one break-scan, for the ending
// space), then tail-calls the path-length stage. Request-line work stays in
// the entry because a tail call cannot target the attached entry program.
SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_http, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!cgroup_is_tracked(current_cgroup_id()))
        return 0;
    if (http_entry_capture(msg) < 0)
        return 0;
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    if (http_step_reqline(s) < 0)
        return 0;
    bpf_tail_call(ctx, &http_stages, HTTP_STAGE_PATHLEN);
    return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_http_pathlen, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    if (http_step_pathlen(s) < 0)
        return 0;
    bpf_tail_call(ctx, &http_stages, HTTP_STAGE_PATHCOPY);
    return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_http_pathcopy, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    if (http_step_pathcopy(s) < 0)
        return 0;
    bpf_tail_call(ctx, &http_stages, HTTP_STAGE_HOSTFIND);
    return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_http_hostfind, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    if (http_step_hostfind(s) < 0)
        return 0;
    bpf_tail_call(ctx, &http_stages, HTTP_STAGE_HOSTLEN);
    return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_http_hostlen, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    if (http_step_hostlen(s) < 0)
        return 0;
    bpf_tail_call(ctx, &http_stages, HTTP_STAGE_HOSTCOPY);
    return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_http_hostcopy, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    if (http_step_hostcopy(s) < 0)
        return 0;
    bpf_tail_call(ctx, &http_stages, HTTP_STAGE_EMIT);
    return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_http_emit, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    http_step_emit(s, current_cgroup_id());
    return 0;
}
