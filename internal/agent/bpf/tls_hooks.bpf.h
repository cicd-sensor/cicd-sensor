// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// Our vendored vmlinux.h is x86-derived, so `struct user_pt_regs` (what
// bpf_tracing.h casts to for arm64 PT_REGS_PARM access) is only forward-
// declared. Complete it here for the arm64 build with the ABI-stable layout
// (this is exactly the aarch64 uapi user_pt_regs). The x86 build uses the
// vmlinux `struct pt_regs` and skips this. Uprobe args are read by direct
// register offset, not CO-RE, so this fixed layout is correct.
#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};
#endif

// tls_hooks.bpf.h — HTTPS request-line capture at the OpenSSL boundary.
//
// HTTPS is TLS ciphertext by the time it reaches tcp_sendmsg, so the cleartext
// tap cannot read it. This taps the plaintext one layer earlier: a uprobe on
// SSL_write / SSL_write_ex reads the request buffer the application hands to
// OpenSSL, before encryption. Userspace discovers and attaches these to the
// libssl inode (or a statically-linked binary); the cgroup gate scopes emission
// to tracked jobs, exactly like the cleartext tap.
//
// The parse is identical to the cleartext tap and reuses the same in-eBPF
// steps, the same per-CPU http_scratch, and the same http_request_sample; only
// the buffer source (a user pointer instead of a msghdr segment) and the
// emitted `source` tag differ. Because a uprobe program is kprobe-type, its
// tail-call target cannot be the fentry-type http_stages target — it uses its
// own http_tls_stages jump table with a kprobe-type parse program.
//
//   SSL_write(ssl, buf, num)  /  SSL_write_ex(ssl, buf, num, *written)
//      |  (one entry program attached to both symbols)
//      v
//   entry ─── cgroup gate → capture ≤256B of buf → parse request line
//      |  bpf_tail_call(http_tls_stages[0])
//      v
//   [0] parse   path scan → Host scan → reserve/copy/submit (source=openssl)

// Stage index in the http_tls_stages jump table.
#define HTTP_TLS_STAGE_PARSE 0

// Entry: PARM2 is the plaintext buffer, PARM3 its length, for both
// SSL_write(SSL*, const void*, int) and
// SSL_write_ex(SSL*, const void*, size_t, size_t*). One program is attached to
// both symbols by userspace. num is checked as signed before the unsigned
// capture so a negative/short length is rejected without a huge cast.
SEC("uprobe/SSL_write")
int BPF_UPROBE(handle_ssl_write, void *ssl, const void *buf, long num)
{
    if (!cgroup_is_tracked(current_cgroup_id()))
        return 0;
    if (num < HTTP_MIN_REQUEST_LINE)
        return 0;
    if (http_capture_user_buffer(buf, (__u64)num) < 0)
        return 0;
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    if (http_step_reqline(s) < 0)
        return 0;
    bpf_tail_call(ctx, &http_tls_stages, HTTP_TLS_STAGE_PARSE);
    return 0;
}

// Parse target: reached only via bpf_tail_call, never attached, so its SEC only
// serves to make it kprobe-type (matching the entry). Same steps as the
// cleartext parse target; emits with source = openssl.
SEC("uprobe/SSL_write")
int BPF_UPROBE(handle_ssl_write_parse)
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
    http_step_emit(s, current_cgroup_id(), HTTP_SOURCE_OPENSSL);
    return 0;
}
