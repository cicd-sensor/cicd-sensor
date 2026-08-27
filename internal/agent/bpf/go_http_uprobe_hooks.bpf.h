// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// Go net/http capture at Transport.roundTrip entry. The selected Go versions
// use ABIInternal: the receiver is the first integer argument and *Request is
// the second (RBX on amd64, R1 on arm64). Go does not promise this ABI or these
// object offsets; unsupported layouts must fail validation without emitting.

#define GO_HTTP_REQUEST_METHOD_OFFSET 0
#define GO_HTTP_REQUEST_URL_OFFSET    16
#define GO_HTTP_REQUEST_HOST_OFFSET   128
#define GO_HTTP_URL_SCHEME_OFFSET     0
#define GO_HTTP_URL_HOST_OFFSET       40
#define GO_HTTP_URL_PATH_OFFSET       56

struct go_string_abi {
    const __u8 *data;
    __u64 len;
};

_Static_assert(sizeof(struct go_string_abi) == 16,
               "Go string ABI must remain two 64-bit words");

static __always_inline const void *go_http_request_argument(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_x86)
    return (const void *)ctx->bx;
#elif defined(__TARGET_ARCH_arm64)
    return (const void *)((struct user_pt_regs *)ctx)->regs[1];
#else
#error "Go HTTP uprobe supports only amd64 and arm64"
#endif
}

static __always_inline int go_http_read_string(const void *base, __u32 offset,
                                                struct go_string_abi *value)
{
    if (!base)
        return -1;
    return bpf_probe_read_user(value, sizeof(*value), (const char *)base + offset);
}

static __always_inline int go_http_is_https(const struct go_string_abi *scheme)
{
    if (!scheme->data || scheme->len != 5)
        return 0;
    char value[5];
    if (bpf_probe_read_user(value, sizeof(value), scheme->data) < 0)
        return 0;
    return value[0] == 'h' && value[1] == 't' && value[2] == 't' &&
           value[3] == 'p' && value[4] == 's';
}

SEC("uprobe/go_net_http_round_trip")
int handle_go_net_http_round_trip(struct pt_regs *ctx)
{
    __u64 cgroup_id = current_cgroup_id();
    if (!cgroup_is_tracked(cgroup_id))
        return 0;

    const void *request = go_http_request_argument(ctx);
    if (!request)
        return 0;

    const void *url = NULL;
    if (bpf_probe_read_user(&url, sizeof(url),
                            (const char *)request + GO_HTTP_REQUEST_URL_OFFSET) < 0 || !url)
        return 0;

    struct go_string_abi scheme = {};
    if (go_http_read_string(url, GO_HTTP_URL_SCHEME_OFFSET, &scheme) < 0 ||
        !go_http_is_https(&scheme))
        return 0;

    struct go_string_abi method = {};
    if (go_http_read_string(request, GO_HTTP_REQUEST_METHOD_OFFSET, &method) < 0)
        return 0;
    __u32 method_n = 0;
    if (method.len > 0 &&
        http_user_field_length(method.data, method.len, HTTP_METHOD_LEN, 0, &method_n) < 0)
        return 0;

    struct go_string_abi path = {};
    if (go_http_read_string(url, GO_HTTP_URL_PATH_OFFSET, &path) < 0)
        return 0;
    __u32 path_n = 0;
    if (path.len > 0) {
        if (http_user_field_length(path.data, path.len, HTTP_PATH_LEN, 0, &path_n) < 0)
            return 0;
        __u8 first;
        if (bpf_probe_read_user(&first, sizeof(first), path.data) < 0 || first != '/')
            return 0;
    }

    struct go_string_abi host = {};
    if (go_http_read_string(request, GO_HTTP_REQUEST_HOST_OFFSET, &host) < 0)
        return 0;
    if (host.len == 0 && go_http_read_string(url, GO_HTTP_URL_HOST_OFFSET, &host) < 0)
        return 0;
    __u32 host_n = 0;
    int have_host = host.len > 0 &&
                    http_user_field_length(host.data, host.len, HTTP_HOST_LEN, 0, &host_n) == 0;

    struct http_request_sample *sample =
        bpf_ringbuf_reserve(&events, sizeof(*sample), 0);
    if (!sample) {
        note_ringbuf_drop();
        return 0;
    }
    sample->kind = SAMPLE_KIND_HTTP_REQUEST;
    sample->source = HTTP_SOURCE_GO_NET_HTTP;
    sample->_pad0[0] = 0;
    sample->_pad0[1] = 0;
    sample->_pad0[2] = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad1 = 0;
    zero_http_request_fields(sample);

    if (method.len == 0) {
        sample->method[0] = 'G';
        sample->method[1] = 'E';
        sample->method[2] = 'T';
    } else if (http_copy_user_method(sample->method, method.data, method_n) < 0) {
        bpf_ringbuf_discard(sample, 0);
        return 0;
    }
    if (path.len == 0) {
        sample->path[0] = '/';
    } else if (http_copy_user_value(sample->path, path.data, path_n) < 0) {
        bpf_ringbuf_discard(sample, 0);
        return 0;
    }
    if (have_host && http_copy_user_value(sample->host, host.data, host_n) < 0) {
        bpf_ringbuf_discard(sample, 0);
        return 0;
    }

    bpf_ringbuf_submit(sample, 0);
    return 0;
}
