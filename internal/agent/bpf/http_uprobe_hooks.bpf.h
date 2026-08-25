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

// http_uprobe_hooks.bpf.h — HTTP capture at userspace library boundaries.
//
// HTTPS is TLS ciphertext by the time it reaches tcp_sendmsg. SSL_write uprobes
// observe HTTP/1.x before encryption; nghttp2 submission uprobes observe HTTP/2
// pseudo-headers before HPACK. Userspace discovers selected symbols in mapped
// files, and the cgroup gate scopes emission to tracked jobs.
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
// both symbols by userspace. Capture is bounded, but a negative SSL_write int
// is indistinguishable here from a large SSL_write_ex length after zero-extension.
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

// Both selected nghttp2 APIs expose nva as argument 3 and nvlen as argument 4.
// Reading pseudo-headers at this public boundary observes HTTP/2 before HPACK
// while keeping ordinary headers and values out of the ring buffer.
// The fixed limit bounds verifier work; valid pseudo-headers precede regular
// headers, and a normal request needs only a small fixed set.
#define NGHTTP2_MAX_HEADERS 32

struct nghttp2_nv_abi {
    const __u8 *name;
    const __u8 *value;
    __u64 namelen;
    __u64 valuelen;
    __u8 flags;
};

_Static_assert(sizeof(struct nghttp2_nv_abi) == 40,
               "nghttp2_nv ABI must remain 40 bytes on 64-bit Linux");
_Static_assert((HTTP_METHOD_LEN & (HTTP_METHOD_LEN - 1)) == 0,
               "HTTP_METHOD_LEN must be a power of two");
_Static_assert(HTTP_HOST_LEN == HTTP_PATH_LEN,
               "nghttp2 path and authority copies share one bounded helper");

enum nghttp2_pseudo_header {
    NGHTTP2_PSEUDO_OTHER = 0,
    NGHTTP2_PSEUDO_METHOD = 1,
    NGHTTP2_PSEUDO_PATH = 2,
    NGHTTP2_PSEUDO_AUTHORITY = 3,
};

static __always_inline __u8 http_ascii_lower(__u8 c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

static __always_inline int nghttp2_pseudo_header_kind(const struct nghttp2_nv_abi *nv)
{
    char name[10] = {};
    __u32 n;

    switch (nv->namelen) {
    case 5:
        n = 5;
        break;
    case 7:
        n = 7;
        break;
    case 10:
        n = 10;
        break;
    default:
        return NGHTTP2_PSEUDO_OTHER;
    }
    if (bpf_probe_read_user(name, n, nv->name) < 0)
        return -1;

    if (n == 5 && name[0] == ':' && http_ascii_lower(name[1]) == 'p' &&
        http_ascii_lower(name[2]) == 'a' && http_ascii_lower(name[3]) == 't' &&
        http_ascii_lower(name[4]) == 'h')
        return NGHTTP2_PSEUDO_PATH;
    if (n == 7 && name[0] == ':' && http_ascii_lower(name[1]) == 'm' &&
        http_ascii_lower(name[2]) == 'e' && http_ascii_lower(name[3]) == 't' &&
        http_ascii_lower(name[4]) == 'h' && http_ascii_lower(name[5]) == 'o' &&
        http_ascii_lower(name[6]) == 'd')
        return NGHTTP2_PSEUDO_METHOD;
    if (n == 10 && name[0] == ':' && http_ascii_lower(name[1]) == 'a' &&
        http_ascii_lower(name[2]) == 'u' && http_ascii_lower(name[3]) == 't' &&
        http_ascii_lower(name[4]) == 'h' && http_ascii_lower(name[5]) == 'o' &&
        http_ascii_lower(name[6]) == 'r' && http_ascii_lower(name[7]) == 'i' &&
        http_ascii_lower(name[8]) == 't' && http_ascii_lower(name[9]) == 'y')
        return NGHTTP2_PSEUDO_AUTHORITY;
    return NGHTTP2_PSEUDO_OTHER;
}

// nghttp2_field_length validates one selected value and returns the bytes safe
// to emit. Path stops at '?', so query data never crosses the kernel boundary.
static __always_inline int nghttp2_field_length(const __u8 *value, __u64 value_len,
                                                 __u32 field_len, int strip_query,
                                                 __u32 *result)
{
    if (!value || value_len == 0)
        return -1;

    for (int i = 0; i < HTTP_PATH_LEN; i++) {
        if ((__u64)i >= value_len) {
            *result = i;
            return 0;
        }
        __u8 c;
        if (bpf_probe_read_user(&c, sizeof(c), value + i) < 0)
            return -1;
        if (strip_query && c == '?') {
            *result = i;
            return i > 0 ? 0 : -1;
        }
        if (c < 0x20 || c == 0x7f)
            return -1;
        if ((__u32)i + 1 >= field_len)
            return -1;
    }
    return -1;
}

static __always_inline int nghttp2_copy_method(char *dst, const __u8 *src, __u32 n)
{
    if (!src || n == 0 || n >= HTTP_METHOD_LEN)
        return -1;
    asm volatile("" : "+r"(n));
    n &= HTTP_METHOD_LEN - 1;
    return bpf_probe_read_user(dst, n, src);
}

static __always_inline int nghttp2_copy_value(char *dst, const __u8 *src, __u32 n)
{
    if (!src || n == 0 || n >= HTTP_PATH_LEN)
        return -1;
    asm volatile("" : "+r"(n));
    n &= HTTP_PATH_LEN - 1;
    return bpf_probe_read_user(dst, n, src);
}

SEC("uprobe/nghttp2_submit_request")
int BPF_UPROBE(handle_nghttp2_submit_request, void *session, void *pri_spec,
               const struct nghttp2_nv_abi *nva, __u64 nvlen)
{
    __u64 cgroup_id = current_cgroup_id();
    if (!cgroup_is_tracked(cgroup_id) || !nva || nvlen == 0)
        return 0;

    const __u8 *method = NULL;
    const __u8 *path = NULL;
    const __u8 *authority = NULL;
    __u64 method_len = 0;
    __u64 path_len = 0;
    __u64 authority_len = 0;

    for (int i = 0; i < NGHTTP2_MAX_HEADERS; i++) {
        if ((__u64)i >= nvlen)
            break;
        struct nghttp2_nv_abi nv = {};
        if (bpf_probe_read_user(&nv, sizeof(nv), nva + i) < 0)
            return 0;
        if (!nv.name || nv.namelen == 0)
            return 0;

        __u8 first;
        if (bpf_probe_read_user(&first, sizeof(first), nv.name) < 0)
            return 0;
        if (first != ':')
            break;

        int kind = nghttp2_pseudo_header_kind(&nv);
        if (kind < 0)
            return 0;
        if (kind == NGHTTP2_PSEUDO_METHOD && !method) {
            method = nv.value;
            method_len = nv.valuelen;
        } else if (kind == NGHTTP2_PSEUDO_PATH && !path) {
            path = nv.value;
            path_len = nv.valuelen;
        } else if (kind == NGHTTP2_PSEUDO_AUTHORITY && !authority) {
            authority = nv.value;
            authority_len = nv.valuelen;
        }
        if (method && path && authority)
            break;
    }

    __u32 method_n = 0;
    __u32 path_n = 0;
    if (nghttp2_field_length(method, method_len, HTTP_METHOD_LEN, 0, &method_n) < 0)
        return 0;
    if (nghttp2_field_length(path, path_len, HTTP_PATH_LEN, 1, &path_n) < 0)
        return 0;

    __u8 first_path;
    if (bpf_probe_read_user(&first_path, sizeof(first_path), path) < 0 || first_path != '/')
        return 0;

    __u32 authority_n = 0;
    int have_authority = authority &&
        nghttp2_field_length(authority, authority_len, HTTP_HOST_LEN, 0, &authority_n) == 0;

    struct http_request_sample *sample =
        bpf_ringbuf_reserve(&events, sizeof(*sample), 0);
    if (!sample) {
        note_ringbuf_drop();
        return 0;
    }
    sample->kind = SAMPLE_KIND_HTTP_REQUEST;
    sample->source = HTTP_SOURCE_NGHTTP2;
    sample->_pad0[0] = 0;
    sample->_pad0[1] = 0;
    sample->_pad0[2] = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad1 = 0;
    zero_http_request_fields(sample);

    if (nghttp2_copy_method(sample->method, method, method_n) < 0 ||
        nghttp2_copy_value(sample->path, path, path_n) < 0) {
        bpf_ringbuf_discard(sample, 0);
        return 0;
    }
    if (have_authority &&
        nghttp2_copy_value(sample->host, authority, authority_n) < 0) {
        bpf_ringbuf_discard(sample, 0);
        return 0;
    }

    bpf_ringbuf_submit(sample, 0);
    return 0;
}
