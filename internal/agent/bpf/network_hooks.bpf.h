// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// network_hooks.bpf.h — inet connect attempts and userspace AF_UNIX connects.

#define NETWORK_PROTOCOL_TCP 6
#define NETWORK_PROTOCOL_UDP 17

static __always_inline bool is_tcp_or_udp(__u8 protocol)
{
    return protocol == NETWORK_PROTOCOL_TCP || protocol == NETWORK_PROTOCOL_UDP;
}

static __always_inline __u16 sockaddr_user_port(struct bpf_sock_addr *ctx)
{
    // user_port is a __u32 field, but Linux stores the 16-bit port in NBO.
    volatile __u32 port = ctx->user_port;

    return bpf_ntohs((__be16)port);
}

// Attached once to the detected cgroup v2 root. tracked_cgroups keeps this
// observation-only and per-Job without per-Job attach churn; return 1 allows.
SEC("cgroup/connect4")
int handle_cgroup_connect4(struct bpf_sock_addr *ctx)
{
    __u64 cgroup_id = current_cgroup_id();
    __u8 protocol = ctx->protocol;
    __u32 user_ip4 = ctx->user_ip4;

    if (!cgroup_is_tracked(cgroup_id))
        return 1;

    if (!is_tcp_or_udp(protocol))
        return 1;

    __u16 remote_port = sockaddr_user_port(ctx);
    // UDP port 0 is used by runtimes/libc for route or address selection.
    // It is not a meaningful outbound endpoint, so do not surface it.
    if (remote_port == 0)
        return 1;

    RESERVE_SAMPLE(sample, struct net_v4_sample, return 1);

    sample->kind = SAMPLE_KIND_NETWORK_CONNECT_V4;
    sample->protocol = protocol;
    sample->blocked = 0;
    sample->_pad0 = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad1 = 0;
    // Kernel stores user_ip4 as NBO u32. Copying through a local preserves
    // the on-wire byte order regardless of host endianness. Taking
    // &ctx->user_ip4 directly would be PTR_TO_CTX and some verifiers reject
    // it as a memcpy source.
    __builtin_memcpy(sample->remote_ip, &user_ip4, sizeof(sample->remote_ip));
    sample->remote_port = remote_port;
    sample->_pad2 = 0;

    bpf_ringbuf_submit(sample, 0);
    return 1;
}

SEC("cgroup/connect6")
int handle_cgroup_connect6(struct bpf_sock_addr *ctx)
{
    __u64 cgroup_id = current_cgroup_id();
    __u8 protocol = ctx->protocol;
    __u32 user_ip6[4];

    if (!cgroup_is_tracked(cgroup_id))
        return 1;

    if (!is_tcp_or_udp(protocol))
        return 1;

    __u16 remote_port = sockaddr_user_port(ctx);
    // UDP port 0 is used by runtimes/libc for route or address selection.
    // It is not a meaningful outbound endpoint, so do not surface it.
    if (remote_port == 0)
        return 1;

    user_ip6[0] = ctx->user_ip6[0];
    user_ip6[1] = ctx->user_ip6[1];
    user_ip6[2] = ctx->user_ip6[2];
    user_ip6[3] = ctx->user_ip6[3];

    RESERVE_SAMPLE(sample, struct net_v6_sample, return 1);

    sample->kind = SAMPLE_KIND_NETWORK_CONNECT_V6;
    sample->protocol = protocol;
    sample->blocked = 0;
    sample->_pad0 = 0;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->_pad1 = 0;
    // Same NBO-preserving idiom as connect4, extended across 4 u32 words.
    // Element-wise copy is required: ctx->user_ip6 as an array decays to
    // PTR_TO_CTX, which cannot be passed as a memcpy source directly.
    __builtin_memcpy(sample->remote_ip, user_ip6, sizeof(sample->remote_ip));
    sample->remote_port = remote_port;
    sample->_pad2 = 0;

    bpf_ringbuf_submit(sample, 0);
    return 1;
}

// Submits the AF_UNIX connect sample shared by the unix_{stream,dgram}_connect
// fentry programs. The sample keeps enough context for userspace to render the
// three sun_path forms: absolute filesystem paths, Linux abstract namespace
// names, and relative paths resolved from cwd.
//
// The proto_ops entry points see every AF_UNIX connect, including in-kernel
// kernel_connect() callers; connects denied earlier by an LSM never reach them.
static __always_inline int submit_unix_socket_connect(struct socket *sock,
                                                      struct sockaddr *address,
                                                      int addrlen)
{
    if (!address)
        return 0;
    if (addrlen < (int)sizeof(sa_family_t))
        return 0;

    __u64 cgroup_id = current_cgroup_id();
    if (!cgroup_is_tracked(cgroup_id))
        return 0;

    // AF_UNSPEC on a dgram socket is a disconnect request, not an outbound
    // endpoint.
    sa_family_t family = BPF_CORE_READ(address, sa_family);
    if (family != AGENT_AF_UNIX)
        return 0;

    // unix proto_ops already guarantee AF_UNIX; defense in depth.
    __u16 sk_family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
    if (sk_family != AGENT_AF_UNIX)
        return 0;

    // Unnamed socket — nothing to emit.
    int sun_path_len = addrlen - (int)sizeof(family);
    if (sun_path_len <= 0)
        return 0;

    // addrlen is caller-provided; clamp claims beyond sockaddr_un.sun_path.
    int sun_path_truncated = 0;
    if (sun_path_len > UNIX_SOCKET_SUN_PATH_LEN) {
        sun_path_len = UNIX_SOCKET_SUN_PATH_LEN;
        sun_path_truncated = 1;
    }

    RESERVE_SAMPLE(sample, struct unix_socket_connect_sample, return 0);

    sample->kind = SAMPLE_KIND_UNIX_SOCKET_CONNECT;
    SET_TASK_HEADER(sample, cgroup_id);
    sample->socket_type = (__u8)BPF_CORE_READ(sock, type);
    sample->sun_path_len = (__u32)sun_path_len;
    sample->sun_path_truncated = (__u8)sun_path_truncated;
    sample->cwd_truncated = 0;
    sample->cwd_unavailable = 0;
    sample->_pad0 = 0;
    sample->cwd_offset = 0;

    // Keep trailing bytes zero past sun_path_len for stable userspace decode.
    __builtin_memset(sample->sun_path, 0, UNIX_SOCKET_SUN_PATH_LEN);

    __u32 read_len = (__u32)sun_path_len;
    if (read_len > UNIX_SOCKET_SUN_PATH_LEN)
        read_len = UNIX_SOCKET_SUN_PATH_LEN;
    long ret = bpf_probe_read_kernel(sample->sun_path, read_len,
                                     (const char *)address + sizeof(family));
    if (ret < 0) {
        // Drop instead of mis-rendering a failed read as an abstract socket.
        bpf_ringbuf_discard(sample, 0);
        return 0;
    }

    // cwd[] is optional; zero it because ringbuf reservation may be reused.
    zero_path_bytes(sample->cwd);

    __u8 first_byte = sample->sun_path[0];
    sample->is_abstract = (first_byte == 0) ? 1 : 0;

    if (first_byte != 0 && first_byte != '/') {
        if (!copy_current_cwd_fallback_path_to_sample(sample))
            sample->cwd_unavailable = 1;
    }

    bpf_ringbuf_submit(sample, 0);
    return 0;
}

// SOCK_STREAM and SOCK_SEQPACKET share unix_stream_connect through their
// proto_ops, so one program covers both; sock->type records which.
SEC("fentry/unix_stream_connect")
int BPF_PROG(handle_unix_stream_connect,
             struct socket *sock, struct sockaddr *uaddr, int addr_len,
             int flags)
{
    return submit_unix_socket_connect(sock, uaddr, addr_len);
}

SEC("fentry/unix_dgram_connect")
int BPF_PROG(handle_unix_dgram_connect,
             struct socket *sock, struct sockaddr *addr, int alen, int flags)
{
    return submit_unix_socket_connect(sock, addr, alen);
}
