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
// tail-call targets cannot be the fentry-type http_stages target — they use a
// separate http_uprobe_stages jump table with kprobe-type programs.
//
//   SSL_write(ssl, buf, num)  /  SSL_write_ex(ssl, buf, num, *written)
//      |  (one entry program attached to both symbols)
//      v
//   entry ─── cgroup gate → capture ≤256B of buf → parse request line
//      |  bpf_tail_call(http_uprobe_stages[0])
//      v
//   [0] parse   path scan → Host scan → reserve/copy/submit (source=openssl)
//
//   nghttp2_submit_request(2)(..., nva, nvlen, ...)
//      |  scan at most 32 leading pseudo-headers; retain only pointers to
//      |  :method, :path, and :authority in the per-CPU scratch entry
//      v
//   [1] validate required method/path ─→ [2] validate optional host and emit
//
// The tail call resets verifier state after the bounded pseudo-header scan; a
// no-tail-call version exceeded Linux 6.17's one-million-instruction budget.
// Linux 6.17 also needs the three value scans split across two targets. The
// split follows event semantics instead of forming a per-field pipeline.
// Raw header values remain in userspace and only the three selected, validated
// fields are copied to the ring buffer by the tail target.

// Stage indices in the http_uprobe_stages jump table.
#define HTTP_UPROBE_STAGE_OPENSSL_PARSE     0
#define HTTP_UPROBE_STAGE_NGHTTP2_REQUIRED  1
#define HTTP_UPROBE_STAGE_NGHTTP2_EMIT      2

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
    bpf_tail_call(ctx, &http_uprobe_stages, HTTP_UPROBE_STAGE_OPENSSL_PARSE);
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

// nghttp2_submit_request(2) submits one HTTP/2 request as HEADERS plus optional
// DATA. Both APIs have the same first four arguments; request2 only changes the
// later data-provider type:
//
//   (session, pri_spec, nva, nvlen, data_prd, stream_user_data)
//
// nva means "name/value array": it points to nvlen nghttp2_nv entries. A normal
// request starts with pseudo-headers similar to the array below, followed by
// ordinary headers:
//
//   {":method", "GET"}, {":scheme", "https"},
//   {":authority", "example.com"}, {":path", "/build?id=secret"},
//   {"authorization", "..."}, ...
//
// The entry reads argument 3 (nva) and argument 4 (nvlen) before HPACK. It scans
// only the leading pseudo-headers, retains pointers to method/path/authority,
// and stops at the first ordinary header. The fixed entry limit bounds verifier
// work; ordinary header names and values are never copied to the ring buffer.
#define NGHTTP2_MAX_HEADERS 32

// Public nghttp2_nv ABI copied from userspace. The flags byte is not used by
// the parser, but it must remain here so array indexing matches libnghttp2's
// 64-bit layout exactly.
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

// Classify only the three pseudo-headers exposed in http_request. Checking the
// exact public name length before reading bounds the userspace read and avoids
// treating an ordinary or similarly prefixed header as a selected field.
static __always_inline int nghttp2_pseudo_header_kind(const struct nghttp2_nv_abi *nv)
{
    char name[10] = {};
    __u32 n;

    // Skip lengths that cannot be :path, :method, or :authority.
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

// Validate one selected value without copying it. The returned length excludes
// controls, DEL, and field overflow; path stops at '?', so query data never
// crosses the kernel boundary. A value that does not fit completely within the
// field cap is rejected rather than exposed as a silently truncated value.
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
        // Reject ASCII control bytes and DEL from the rule-facing field.
        if (c < 0x20 || c == 0x7f)
            return -1;
        if ((__u32)i + 1 >= field_len)
            return -1;
    }
    return -1;
}

// The comparison enforces the field contract; the opaque mask separately gives
// older verifiers a durable variable-length userspace-read bound.
static __always_inline int nghttp2_copy_method(char *dst, const __u8 *src, __u32 n)
{
    if (!src || n == 0 || n >= HTTP_METHOD_LEN)
        return -1;
    asm volatile("" : "+r"(n));
    n &= HTTP_METHOD_LEN - 1;
    return bpf_probe_read_user(dst, n, src);
}

// Path and authority share the same fixed field size and verifier proof.
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

    // HTTP/2 requires pseudo-headers before regular headers. Stop at the first
    // regular header so credentials and other ordinary headers are never
    // examined. First occurrence wins if a malformed array repeats a field.
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

    // Carry only userspace pointers and lengths into the verifier-split target;
    // no raw header byte is copied into scratch.
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;

    s->nghttp2_method = (__u64)method;
    s->nghttp2_path = (__u64)path;
    s->nghttp2_authority = (__u64)authority;
    s->nghttp2_method_len = method_len;
    s->nghttp2_path_len = path_len;
    s->nghttp2_authority_len = authority_len;
    bpf_tail_call(ctx, &http_uprobe_stages, HTTP_UPROBE_STAGE_NGHTTP2_REQUIRED);
    return 0;
}

// Validate the required fields together: a request needs both method and path.
SEC("uprobe/nghttp2_submit_request")
int BPF_UPROBE(handle_nghttp2_required)
{
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    const __u8 *method = (const __u8 *)s->nghttp2_method;
    const __u8 *path = (const __u8 *)s->nghttp2_path;
    __u32 method_n = 0;
    if (nghttp2_field_length(method, s->nghttp2_method_len,
                             HTTP_METHOD_LEN, 0, &method_n) < 0)
        return 0;
    __u32 path_n = 0;
    if (nghttp2_field_length(path, s->nghttp2_path_len,
                             HTTP_PATH_LEN, 1, &path_n) < 0)
        return 0;

    // Standard HTTP/2 CONNECT intentionally has no :path and is dropped by the
    // previous validation. Other requests, including extended CONNECT, need an
    // origin-form path so rule-facing path semantics stay consistent.
    __u8 first_path;
    if (bpf_probe_read_user(&first_path, sizeof(first_path), path) < 0 || first_path != '/')
        return 0;

    s->nghttp2_method_n = method_n;
    s->nghttp2_path_n = path_n;
    bpf_tail_call(ctx, &http_uprobe_stages, HTTP_UPROBE_STAGE_NGHTTP2_EMIT);
    return 0;
}

// Validate the optional authority, then emit only method, path, and host.
SEC("uprobe/nghttp2_submit_request")
int BPF_UPROBE(handle_nghttp2_emit)
{
    struct http_scratch *s = http_scratch_get();
    if (!s)
        return 0;
    const __u8 *method = (const __u8 *)s->nghttp2_method;
    const __u8 *path = (const __u8 *)s->nghttp2_path;
    const __u8 *authority = (const __u8 *)s->nghttp2_authority;

    // Authority is optional for event emission. An absent or invalid value
    // becomes an empty host; method and path remain useful rule evidence.
    __u32 authority_n = 0;
    int have_authority = 0;
    if (authority && nghttp2_field_length(authority, s->nghttp2_authority_len,
                                          HTTP_HOST_LEN, 0, &authority_n) == 0) {
        have_authority = 1;
    }

    __u64 cgroup_id = current_cgroup_id();
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

    if (nghttp2_copy_method(sample->method, method, s->nghttp2_method_n) < 0 ||
        nghttp2_copy_value(sample->path, path, s->nghttp2_path_n) < 0) {
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
