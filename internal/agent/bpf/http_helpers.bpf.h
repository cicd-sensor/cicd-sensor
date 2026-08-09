// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// http_helpers.bpf.h — in-kernel HTTP/1 request-line + Host parsing.
//
// Redaction invariant: the raw send prefix stays in the per-CPU
// http_scratch workspace. Only the parsed method / path / host bytes are
// ever written into the ringbuf sample; path is terminated at '?' during
// the parse so the query string never enters a sample. Header and body
// bytes (Authorization, Cookie, ...) never cross the kernel boundary.
//
// The parse is best-effort request-start observation (see the design doc):
// a request split across writes yields empty/truncated fields, and only
// origin-form request lines ("GET /path HTTP/1.x") are accepted.

// HTTP_SOURCE_* values are ringbuf ABI and mirror kerneltracker.HTTPSource*.
#define HTTP_SOURCE_CLEARTEXT 0

// Shortest acceptable request line: "GET / HTTP/1.0" (14 bytes).
#define HTTP_MIN_REQUEST_LINE 14

// Zero fixed-size buffers with literal-bound volatile u64 loops for the same
// BPF-backend reason as the zero_* helpers in common_helpers.bpf.h.
static __always_inline void zero_http_host_bytes(char *buf)
{
    volatile __u64 *words = (volatile __u64 *)buf;
    volatile const __u64 zero_word = 0;
    for (int i = 0; i < HTTP_HOST_LEN / 8; i++)
        words[i] = zero_word;
}

// bpf_ringbuf_reserve does not zero its storage and the buffer is reused, so
// every parsed-field byte and padding must be zeroed before partial writes —
// otherwise stale bytes from a previous sample could leak past the parsed
// fields. This is part of the redaction invariant, not an optimization.
static __always_inline void zero_http_request_fields(struct http_request_sample *sample)
{
    volatile const __u64 zero_word = 0;
    volatile __u64 *words = (volatile __u64 *)sample->method;
    for (int i = 0; i < HTTP_METHOD_LEN / 8; i++)
        words[i] = zero_word;
    words = (volatile __u64 *)sample->path;
    for (int i = 0; i < HTTP_PATH_LEN / 8; i++)
        words[i] = zero_word;
    zero_http_host_bytes(sample->host);
}

// http_method_len matches a known request-method token + space at the start
// of buf (which must hold at least 8 readable bytes) and returns the token
// length, or 0 when the bytes cannot start an HTTP request. CONNECT is
// intentionally absent: its authority-form target never passes the
// origin-form ('/') check below, so matching it would only cost cycles.
static __always_inline __u32 http_method_len(const char *b)
{
    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ')
        return 3;
    if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T' && b[3] == ' ')
        return 3;
    if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T' && b[4] == ' ')
        return 4;
    if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D' && b[4] == ' ')
        return 4;
    if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && b[4] == 'H' &&
        b[5] == ' ')
        return 5;
    if (b[0] == 'T' && b[1] == 'R' && b[2] == 'A' && b[3] == 'C' && b[4] == 'E' &&
        b[5] == ' ')
        return 5;
    if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && b[4] == 'T' &&
        b[5] == 'E' && b[6] == ' ')
        return 6;
    if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && b[4] == 'O' &&
        b[5] == 'N' && b[6] == 'S' && b[7] == ' ')
        return 7;
    return 0;
}

// http_is_ctrl: one deterministic terminator policy — any control byte
// (including CR / LF / NUL) or DEL ends the field it appears in.
static __always_inline int http_is_ctrl(char c)
{
    return (__u8)c < 0x20 || (__u8)c == 0x7f;
}

// http_prefix_byte reads prefix[idx] masked to the buffer. The barrier makes
// idx opaque to clang so it cannot prove the index in range and delete the
// mask; the mask is then the verifier's in-bounds proof. Each pipeline stage
// runs at most one break-scan over the prefix, so the per-read scalar does not
// accumulate into a state explosion (the monolithic parser's failure mode).
static __always_inline char http_prefix_byte(struct http_scratch *s, __u32 idx)
{
    asm volatile("" : "+r"(idx));
    idx &= HTTP1_PREFIX_LEN - 1;
    return s->prefix[idx];
}

// Keep explicit masks in the BPF instructions so Linux 6.6 sees bounded source
// and size registers for a variable-length read into ringbuf memory.
static __always_inline void http_copy_field(char *dst, struct http_scratch *s,
                                            __u32 src, __u32 n)
{
    if (n == 0 || n >= HTTP1_PREFIX_LEN)
        return;
    if (src >= HTTP1_PREFIX_LEN)
        return;
    asm volatile("" : "+r"(src), "+r"(n));
    src &= HTTP1_PREFIX_LEN - 1;
    n &= HTTP1_PREFIX_LEN - 1;
    if (src + n > HTTP1_PREFIX_LEN)
        return;
    bpf_probe_read_kernel(dst, n, &s->prefix[src]);
}

// http_scratch_get returns the single per-CPU parse workspace entry.
static __always_inline struct http_scratch *http_scratch_get(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&http_scratch, &key);
}

// The only state persisted across stages beyond the parse offsets is
// http_scratch.have_host (1 = a host value was captured). The parse captures
// what it can and leaves anything it cannot as empty — there is no truncation
// signal, rules match the value or its absence, nothing finer. A "no host"
// outcome needs no flag: the host stages simply find nothing and leave
// have_host at 0.

// The parse is a tail-call pipeline. Each step below runs in its own BPF
// program (http_hooks.bpf.h) so it gets fresh verifier state and a fresh
// compiler scope; a single program that did all of this could not be made to
// pass the 5.15 / 6.6 / 6.18 verifiers at once (see the design doc). Each step
// re-reads its inputs from the scratch map — the verifier treats a map load as
// an unknown scalar, so the explicit `>=` bound checks below survive and hand
// it clean ranges. Every step runs at most one break-scan over the prefix.
//
// A step returns 0 to continue the pipeline (the program then tail-calls the
// next stage) or -1 to drop (the program returns without tail-calling).

// Step: request line. Method token, origin-form '/', scan to the ending space,
// and validate " HTTP/1.". Stores pos / mlen / line_end / flags.
static __always_inline int http_step_reqline(struct http_scratch *s)
{
    __u32 data_len = s->data_len;
    if (data_len > HTTP1_PREFIX_LEN)
        data_len = HTTP1_PREFIX_LEN;
    if (data_len < HTTP_MIN_REQUEST_LINE)
        return -1;

    __u32 mlen = http_method_len(s->prefix);
    if (!mlen)
        return -1;
    __u32 pos = mlen + 1;
    if (http_prefix_byte(s, pos) != '/')
        return -1;

    __u32 line_end = data_len;
    __u8 space_found = 0;
    for (int i = 0; i < HTTP1_PREFIX_LEN; i++) {
        __u32 idx = pos + i;
        if (idx >= data_len)
            break;
        char c = http_prefix_byte(s, idx);
        if (c == ' ') {
            line_end = idx;
            space_found = 1;
            break;
        }
        if (http_is_ctrl(c))
            return -1;
    }

    // When a space was found and the version token fits in the captured prefix,
    // validate " HTTP/1.<digit>\r" so "GET /x junk" is not accepted as HTTP. If
    // the request line ran past the prefix (no space) or the version token is
    // cut at the boundary, that is an accepted partial capture: keep the path
    // and let the host stages find nothing (have_host stays 0). The version
    // bytes are read only inside the length guard, so no read reaches past
    // data_len — which is why the prefix does not need pre-zeroing.
    if (space_found) {
        __u32 after_space = line_end + 1;
        if (after_space + 7 <= data_len) {
            __u8 v_ok = http_prefix_byte(s, after_space + 0) == 'H' &&
                        http_prefix_byte(s, after_space + 1) == 'T' &&
                        http_prefix_byte(s, after_space + 2) == 'T' &&
                        http_prefix_byte(s, after_space + 3) == 'P' &&
                        http_prefix_byte(s, after_space + 4) == '/' &&
                        http_prefix_byte(s, after_space + 5) == '1' &&
                        http_prefix_byte(s, after_space + 6) == '.';
            if (!v_ok)
                return -1;
            if (after_space + 9 <= data_len) {
                // Full "HTTP/1.<digit>\r": validate the minor digit and the
                // request-line CR so "HTTP/1.Xjunk" is not accepted as HTTP.
                char minor = http_prefix_byte(s, after_space + 7);
                if (minor < '0' || minor > '9' ||
                    http_prefix_byte(s, after_space + 8) != '\r')
                    return -1;
            }
            // Else the minor digit / CR is past the prefix: accept the token.
        }
        // Else the version token is cut at the prefix boundary: accept.
    }

    s->data_len = data_len;
    s->mlen = mlen;
    s->pos = pos;
    s->line_end = line_end;
    return 0;
}

// Step: path length. Scan for '?' (query stripped, never copied) up to the
// request-line space; compute path_n (capped to the path field).
static __always_inline int http_step_pathlen(struct http_scratch *s)
{
    __u32 data_len = s->data_len;
    if (data_len > HTTP1_PREFIX_LEN)
        data_len = HTTP1_PREFIX_LEN;
    __u32 pos = s->pos;
    if (pos >= HTTP1_PREFIX_LEN)
        return -1;
    __u32 line_end = s->line_end;
    if (line_end > data_len)
        line_end = data_len;
    if (line_end < pos)
        line_end = pos;

    __u32 path_end = line_end;
    for (int i = 0; i < HTTP1_PREFIX_LEN; i++) {
        __u32 idx = pos + i;
        if (idx >= line_end)
            break;
        if (http_prefix_byte(s, idx) == '?') {
            path_end = idx;
            break;
        }
    }

    __u32 path_n = path_end - pos;
    if (path_n >= HTTP_PATH_LEN)
        path_n = HTTP_PATH_LEN - 1;

    s->path_n = path_n;
    return 0;
}

// Step: find the Host header value start. Scans for "\r\nHost:" (case-
// insensitive), stopping at the "\r\n\r\n" end of headers so a "Host:" in the
// body cannot false-match. Sets have_host + host_val when found; otherwise
// leaves have_host at 0 and the host is emitted empty.
static __always_inline int http_step_hostfind(struct http_scratch *s)
{
    __u32 data_len = s->data_len;
    if (data_len > HTTP1_PREFIX_LEN)
        data_len = HTTP1_PREFIX_LEN;
    __u32 after_space = s->line_end + 1;
    if (after_space > data_len)
        after_space = data_len;

    __u32 host_val = 0;
    for (int i = 0; i < HTTP1_PREFIX_LEN; i++) {
        __u32 p = after_space + i;
        if (p + 1 >= data_len)
            break;
        if (http_prefix_byte(s, p) != '\r' ||
            http_prefix_byte(s, p + 1) != '\n')
            continue;
        if (p + 3 < data_len &&
            http_prefix_byte(s, p + 2) == '\r' &&
            http_prefix_byte(s, p + 3) == '\n')
            break;   // end of headers reached before any Host: leave empty.
        if (p + 6 >= data_len)
            break;
        if ((http_prefix_byte(s, p + 2) | 0x20) == 'h' &&
            (http_prefix_byte(s, p + 3) | 0x20) == 'o' &&
            (http_prefix_byte(s, p + 4) | 0x20) == 's' &&
            (http_prefix_byte(s, p + 5) | 0x20) == 't' &&
            http_prefix_byte(s, p + 6) == ':') {
            host_val = p + 7;
            break;
        }
    }

    if (!host_val)
        return 0;   // no Host in the prefix: emit with an empty host.

    if (host_val > data_len)
        host_val = data_len;
    // Leading/trailing OWS around the Host value is stripped in userspace
    // (handleHTTPRequestSample), not here: an in-kernel skip capped at a fixed
    // width would leave residual leading whitespace, and trailing whitespace
    // would survive to the copy — both let an attacker dodge a `host == "..."`
    // rule. Userspace trims all of it after decode.
    s->host_val = host_val;
    s->have_host = 1;
    return 0;
}

// Step: find the Host value terminator. Sets host_n, or clears have_host (emit
// an empty host) when the value is unterminated or oversize — a silently cut
// host must not feed host rules.
static __always_inline int http_step_hostlen(struct http_scratch *s)
{
    if (!s->have_host)
        return 0;

    __u32 data_len = s->data_len;
    if (data_len > HTTP1_PREFIX_LEN)
        data_len = HTTP1_PREFIX_LEN;
    __u32 host_val = s->host_val;
    if (host_val > data_len)
        host_val = data_len;

    // The Host value ends at the header line's CR/LF, not at any control byte:
    // a bare CR/LF is the only valid terminator (RFC 9112 §5). An embedded
    // control byte (e.g. NUL) is left in the value and rejected in userspace,
    // so it cannot silently truncate the host into a benign-looking prefix.
    __u32 host_end = data_len;
    __u8 host_terminated = 0;
    for (int i = 0; i < HTTP1_PREFIX_LEN; i++) {
        __u32 p = host_val + i;
        if (p >= data_len)
            break;
        char c = http_prefix_byte(s, p);
        if (c == '\r' || c == '\n') {
            host_end = p;
            host_terminated = 1;
            break;
        }
    }

    __u32 host_n = host_end - host_val;
    if (!host_terminated || host_n >= HTTP_HOST_LEN) {
        s->have_host = 0;
        return 0;
    }
    s->host_n = host_n;
    return 0;
}

// Step: emit. Reserve the ringbuf sample, copy the bounded method/path/host
// fields out of the prefix, set the header, and submit. The ringbuf reservation
// is taken here and nowhere earlier: a live reference cannot survive a tail
// call.
static __always_inline int http_step_emit(struct http_scratch *s, __u64 cgroup_id)
{
    __u32 mlen = s->mlen;
    if (mlen < 3)
        mlen = 3;
    if (mlen > 7)
        mlen = 7;

    struct http_request_sample *sample =
        bpf_ringbuf_reserve(&events, sizeof(*sample), 0);
    if (!sample) {
        note_ringbuf_drop();
        return 0;
    }
    sample->kind = SAMPLE_KIND_HTTP_REQUEST;
    sample->source = HTTP_SOURCE_CLEARTEXT;
    sample->_pad0[0] = 0;
    sample->_pad0[1] = 0;
    sample->_pad0[2] = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad1 = 0;
    zero_http_request_fields(sample);

#pragma unroll
    for (int i = 0; i < 8; i++) {
        if ((__u32)i >= mlen)
            break;
        sample->method[i] = s->prefix[i];
    }
    http_copy_field(sample->path, s, s->pos, s->path_n);
    if (s->have_host)
        http_copy_field(sample->host, s, s->host_val, s->host_n);

    bpf_ringbuf_submit(sample, 0);
    return 0;
}

// http_first_segment resolves the first contiguous user buffer of a sendmsg.
// Request line + Host virtually always live in the first segment; a
// writev-split header block is an accepted gap (the host is emitted empty).
static __always_inline int http_first_segment(struct msghdr *msg,
                                              const void **base,
                                              __u64 *seg_len)
{
    struct iov_iter *iter = &msg->msg_iter;
    __u32 type = BPF_CORE_READ(iter, iter_type);

    // 6.0+ may expose userspace sendmsg data as one ITER_UBUF buffer.
    if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
        type == bpf_core_enum_value(enum iter_type, ITER_UBUF)) {
        void *ubuf = (void *)BPF_CORE_READ(iter, ubuf);
        __u64 count = BPF_CORE_READ(iter, count);
        if (!ubuf || count == 0)
            return -1;
        *base = ubuf;
        *seg_len = count;
        return 0;
    }

    // Other iterator types are kernel-internal paths, not userspace sends.
    if (type != bpf_core_enum_value(enum iter_type, ITER_IOVEC))
        return -1;

    // 6.10+ renamed iov_iter.iov to __iov; older kernels use the legacy name.
    const struct iovec *iov;
    if (bpf_core_field_exists(iter->__iov)) {
        iov = BPF_CORE_READ(iter, __iov);
    } else {
        struct iov_iter___legacy *legacy = (struct iov_iter___legacy *)iter;
        iov = BPF_CORE_READ(legacy, iov);
    }
    if (!iov)
        return -1;

    struct iovec first = {};
    if (bpf_probe_read_kernel(&first, sizeof(first), iov) < 0)
        return -1;
    if (!first.iov_base || first.iov_len == 0)
        return -1;
    *base = first.iov_base;
    *seg_len = first.iov_len;
    return 0;
}

// http_entry_capture resolves the first send segment, rejects non-HTTP with a
// cheap method-token pre-check, copies a bounded prefix into the scratch map,
// and initializes the pipeline state. Returns 0 to start the pipeline (the
// entry program then tail-calls the first stage) or -1 to stop.
static __always_inline int http_entry_capture(struct msghdr *msg)
{
    const void *base = NULL;
    __u64 seg_len = 0;
    if (http_first_segment(msg, &base, &seg_len) < 0)
        return -1;
    if (seg_len < HTTP_MIN_REQUEST_LINE)
        return -1;

    // Cheap pre-check before any large copy: 8 bytes + token compare reject
    // TLS records (0x16/0x17 first byte), binary protocols, and body chunks.
    char head[8] = {};
    if (bpf_probe_read_user(head, sizeof(head), base) < 0)
        return -1;
    if (!http_method_len(head))
        return -1;

    struct http_scratch *s = http_scratch_get();
    if (!s)
        return -1;

    // The prefix is NOT pre-zeroed: data_len is set to exactly the bytes read
    // and every parse scan is bounded by data_len, so stale bytes past it are
    // never read (the version check reads only inside its length guard — see
    // http_step_reqline) and never copied into a sample.
    __u32 to_read = HTTP1_PREFIX_LEN;
    if (seg_len < HTTP1_PREFIX_LEN)
        to_read = (__u32)seg_len;
    if (bpf_probe_read_user(s->prefix, to_read, base) < 0)
        return -1;

    s->data_len = to_read;
    s->have_host = 0;
    s->host_val = 0;
    s->host_n = 0;
    return 0;
}
