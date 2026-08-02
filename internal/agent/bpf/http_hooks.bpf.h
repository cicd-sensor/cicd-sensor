// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// http_hooks.bpf.h — cleartext HTTP request-line capture.
//
// The parse is a tail-call pipeline (see http_helpers.bpf.h and the design
// doc). The entry program below is the only one attached to tcp_sendmsg; the
// stage programs are installed in the http_stages PROG_ARRAY by userspace and
// reached via bpf_tail_call. Each stage runs with fresh verifier state, which
// is what makes the whole parse loadable on Linux 5.15 / 6.6 / 6.18 — a single
// monolithic program could not be. Path/host are copied into per-CPU staging
// fields by their own stages because 6.6 rejects a variable-length read into
// the ringbuf sample; the host stage then does a fixed-size memcpy out.

// Stage indices in the http_stages jump table.
#define HTTP_STAGE_PATH     0

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
    bpf_tail_call(ctx, &http_stages, HTTP_STAGE_PATH);
    return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_http_path, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    if (http_step_path(s) < 0)
        return 0;
    if (http_step_hostfind(s) < 0)
        return 0;
    if (http_step_host(s) < 0)
        return 0;
    http_step_emit(s, current_cgroup_id());
    return 0;
}
