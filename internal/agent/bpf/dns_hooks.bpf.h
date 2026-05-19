// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// dns_hooks.bpf.h — DNS sendmsg hooks.

// DNS observation is prefix-based, not wire-faithful reconstruction. Normal
// queries carry QNAME near the start, so bounded sendmsg capture is enough for
// job attribution; corked, fragmented, or adversarial layouts are best-effort.

// Resolver-style observation: udp_sendmsg fires before the kernel assembles
// the datagram, so MSG_MORE / UDP_CORK can split one wire packet into
// multiple samples. Post-assembly fidelity would need an SKB path; on 5.15
// that is much harder without newer dynptr support.
SEC("fentry/udp_sendmsg")
int BPF_PROG(handle_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 cgroup_id = current_cgroup_id();
    if (!cgroup_is_tracked(cgroup_id))
        return 0;

    return submit_dns_query_v4(DNS_SOURCE_UDP, sk, msg, cgroup_id);
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(handle_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 cgroup_id = current_cgroup_id();
    if (!cgroup_is_tracked(cgroup_id))
        return 0;

    return submit_dns_query_v6(DNS_SOURCE_UDP, sk, msg, cgroup_id);
}

// tcp_sendmsg covers AF_INET and AF_INET6 on 5.15+. We branch on sk_family.
// TCP DNS includes the RFC 1035 two-byte length prefix; userspace parses the
// raw sendmsg prefix and drops fragmented queries it cannot decode.
SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 cgroup_id = current_cgroup_id();
    if (!cgroup_is_tracked(cgroup_id))
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AGENT_AF_INET)
        return submit_dns_query_v4(DNS_SOURCE_TCP, sk, msg, cgroup_id);
    if (family == AGENT_AF_INET6)
        return submit_dns_query_v6(DNS_SOURCE_TCP, sk, msg, cgroup_id);
    return 0;
}

// nss-resolve writes JSON queries to systemd-resolved's Varlink unix socket.
// Hooking unix_stream_sendmsg preserves the caller's cgroup; observing
// systemd-resolved's UDP/TCP sends would attribute the query to the daemon.
// Userspace parses ResolveHostname and ignores other Varlink methods.
SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(handle_unix_stream_sendmsg, struct socket *sock, struct msghdr *msg, size_t size)
{
    __u64 cgroup_id = current_cgroup_id();
    if (!cgroup_is_tracked(cgroup_id))
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    // Connected unix stream destinations live on the peer unix_sock address.
    struct unix_sock *u = (struct unix_sock *)sk;
    struct sock *peer = BPF_CORE_READ(u, peer);
    if (!peer)
        return 0;
    struct unix_sock *u_peer = (struct unix_sock *)peer;
    struct unix_address *addr = BPF_CORE_READ(u_peer, addr);
    if (!addr)
        return 0;

    // unix_address.len includes sun_family. Accept optional trailing NUL;
    // the byte compare below still rejects prefix mismatches.
    int addr_len = BPF_CORE_READ(addr, len);
    if (addr_len < (int)(2 + SYSTEMD_RESOLVED_VARLINK_PATH_LEN))
        return 0;

    // sun_family is 2 bytes; sun_path begins at offset 2 of sockaddr_un.
    const void *sun_path_ptr = (const char *)&addr->name[0] + 2;
    char path_buf[SYSTEMD_RESOLVED_VARLINK_PATH_LEN] = {};
    if (bpf_probe_read_kernel(path_buf, SYSTEMD_RESOLVED_VARLINK_PATH_LEN, sun_path_ptr) < 0)
        return 0;

#pragma unroll
    for (int i = 0; i < (int)SYSTEMD_RESOLVED_VARLINK_PATH_LEN; i++) {
        if (path_buf[i] != systemd_resolved_target_path[i])
            return 0;
    }

    // Varlink has no IP family or DNS port; zero values keep diagnostics clean.
    struct dns_sample *sample = reserve_dns_sample(DNS_SOURCE_SYSTEMD_RESOLVED, 0, 0, cgroup_id);
    if (!sample)
        return 0;

    __u32 written = 0;
    if (fill_dns_payload(msg, sample->payload, &written) < 0) {
        bpf_ringbuf_discard(sample, 0);
        return 0;
    }
    sample->payload_len = written;
    bpf_ringbuf_submit(sample, 0);
    return 0;
}
