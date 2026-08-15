// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// http_hooks.bpf.h — cleartext HTTP request-line capture.
//
// The parse is split once with a tail call (see http_helpers.bpf.h and the
// design doc). The entry program below is the only one attached to tcp_sendmsg;
// userspace installs the parse target in http_stages. The verifier reset keeps
// the whole parse loadable on Linux 5.15 / 6.6 / 6.18; a single monolithic
// program exceeds the verifier instruction budget. The target copies only the
// bounded path/host fields into the sample.
//
//   kernel: tcp_sendmsg
//      |  (only this program is attached)
//      v
//   entry ─── cgroup gate → capture ≤256B prefix → parse request line
//      |
//      |  bpf_tail_call(http_stages[0]); a missing target drops the capture.
//      v
//   [0] parse      path scan → Host scan → reserve/copy/submit
//
// Both programs share the per-CPU http_scratch workspace because tail calls do
// not migrate execution to another CPU. They carry the same
// SEC("fentry/tcp_sendmsg") and signature not because both hook tcp_sendmsg,
// but because bpf_tail_call requires a compatible target program.

// Stage indices in the http_stages jump table.
#define HTTP_STAGE_PARSE 0

// Entry: content detection separates cleartext from ciphertext (a TLS write
// starts with a record byte and never matches a method token; KTLS plaintext
// is intercepted before tcp_sendmsg). On a match it copies the prefix into the
// scratch map and parses the request line (one break-scan, for the ending
// space), then tail-calls the parse target. Request-line work stays in
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
    bpf_tail_call(ctx, &http_stages, HTTP_STAGE_PARSE);
    return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_http_parse, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    if (http_step_path(s) < 0)
        return 0;
    if (http_step_hostfind(s) < 0)
        return 0;
    if (http_step_hostlen(s) < 0)
        return 0;
    http_step_emit(s, current_cgroup_id(), HTTP_SOURCE_CLEARTEXT);
    return 0;
}
