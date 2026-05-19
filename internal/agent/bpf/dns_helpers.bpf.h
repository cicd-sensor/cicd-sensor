// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// dns_helpers.bpf.h — DNS payload extraction and DNS sample emission helpers.

// Plain DNS over UDP/TCP. Other sendmsg calls are ignored in-kernel.
#define DNS_PORT 53
// DNS_SOURCE_* values are ringbuf ABI and mirror kerneltracker.DNSSource*.
#define DNS_SOURCE_UDP 0
#define DNS_SOURCE_TCP 1
#define DNS_SOURCE_SYSTEMD_RESOLVED 2
// systemd-resolved Varlink socket used by nss-resolve.
#define SYSTEMD_RESOLVED_VARLINK_PATH "/run/systemd/resolve/io.systemd.Resolve"
#define SYSTEMD_RESOLVED_VARLINK_PATH_LEN (sizeof(SYSTEMD_RESOLVED_VARLINK_PATH) - 1)
// Maximum struct iovec entries inspected from msg_iter for one DNS sample.
// Normal DNS sends are 1-2 entries; 8 keeps the unrolled loop small for 5.15.
#define DNS_MAX_IOVEC_ENTRIES 8
// Literal read size keeps the 5.15 verifier away from variable-size proof paths.
#define DNS_PER_IOV_MAX 256
_Static_assert((DNS_PER_IOV_MAX & (DNS_PER_IOV_MAX - 1)) == 0,
               "DNS_PER_IOV_MAX must be a power of two");
_Static_assert(DNS_PAYLOAD_LEN >= DNS_PER_IOV_MAX,
               "DNS_PAYLOAD_LEN must hold at least one chunk");
_Static_assert((DNS_PAYLOAD_LEN % DNS_PER_IOV_MAX) == 0,
               "DNS_PAYLOAD_LEN must be a multiple of DNS_PER_IOV_MAX");

// Linux 5.15-6.9 name this field `iov`; 6.10+ renamed it to `__iov`.
// Our vmlinux.h is newer, so this minimal shadow lets CO-RE emit a
// relocation for the old field name. preserve_access_index keeps that
// synthetic field access visible to clang/BTF.
struct iov_iter___legacy {
    const struct iovec *iov;
} __attribute__((preserve_access_index));

// 6.0+ single user buffer path. count is the logical send length.
static __always_inline int fill_dns_payload_from_ubuf(struct iov_iter *iter,
                                                      __u8 *out_buf,
                                                      __u32 *out_len)
{
    __u32 written = 0;
    void *base = (void *)BPF_CORE_READ(iter, ubuf);
    __u64 count = BPF_CORE_READ(iter, count);

    if (!base || count == 0) {
        *out_len = written;
        return 0;
    }

    __u32 to_read = DNS_PAYLOAD_LEN;
    if (count < DNS_PAYLOAD_LEN)
        to_read = (__u32)count;
    if (to_read > DNS_PAYLOAD_LEN)
        to_read = DNS_PAYLOAD_LEN;
    if (to_read != 0 && bpf_probe_read_user(out_buf, to_read, base) == 0)
        written = to_read;

    *out_len = written;
    return 0;
}

// Copy a best-effort DNS payload prefix from a userspace iovec array.
// The loop concatenates up to DNS_MAX_IOVEC_ENTRIES segments into out_buf, capped by
// DNS_PAYLOAD_LEN. Keep the read shape verifier-simple for 5.15: bounded
// unroll, masked offset, and literal 256B reads.
static __always_inline int fill_dns_payload_from_iov_array(const struct iovec *iov,
                                                           __u64 nr_segs,
                                                           __u8 *out_buf,
                                                           __u32 *out_len)
{
    __u32 written = 0;

#pragma unroll
    for (int i = 0; i < DNS_MAX_IOVEC_ENTRIES; i++) {
        // nr_segs is runtime data; DNS_MAX_IOVEC_ENTRIES gives the verifier a fixed loop bound.
        if (i >= (int)nr_segs)
            break;
        if (written >= DNS_PAYLOAD_LEN)
            break;
        struct iovec one = {};
        // Read the iovec descriptor from kernel memory, then its base from user memory.
        if (bpf_probe_read_kernel(&one, sizeof(one), &iov[i]) < 0)
            break;
        if (!one.iov_base || one.iov_len == 0)
            continue;
        // DNS_PAYLOAD_LEN is power-of-two, so this bitmask bounds offset to payload[].
        __u32 offset = written & (DNS_PAYLOAD_LEN - 1);
        // The guard proves out_buf[offset:offset+256] stays within payload[].
        if (offset > DNS_PAYLOAD_LEN - DNS_PER_IOV_MAX)
            break;
        if (bpf_probe_read_user(out_buf + offset, DNS_PER_IOV_MAX,
                                one.iov_base) != 0)
            continue;
        // We read a verifier-friendly 256B literal, but expose only logical bytes.
        __u32 credit = one.iov_len < DNS_PER_IOV_MAX
                           ? (__u32)one.iov_len
                           : DNS_PER_IOV_MAX;
        written += credit;
    }

    *out_len = written;
    return 0;
}

// 6.10+ ITER_IOVEC path: iov_iter exposes the iovec array as `__iov`.
static __always_inline int fill_dns_payload_from_iovec_current(struct iov_iter *iter,
                                                               __u8 *out_buf,
                                                               __u32 *out_len)
{
    const struct iovec *iov = BPF_CORE_READ(iter, __iov);
    __u64 nr_segs = BPF_CORE_READ(iter, nr_segs);

    return fill_dns_payload_from_iov_array(iov, nr_segs, out_buf, out_len);
}

// 5.15-6.9 ITER_IOVEC path: the same field was named `iov`.
static __always_inline int fill_dns_payload_from_iovec_legacy(struct iov_iter *iter,
                                                              __u8 *out_buf,
                                                              __u32 *out_len)
{
    struct iov_iter___legacy *legacy = (struct iov_iter___legacy *)iter;
    const struct iovec *iov = BPF_CORE_READ(legacy, iov);
    __u64 nr_segs = BPF_CORE_READ(iter, nr_segs);

    return fill_dns_payload_from_iov_array(iov, nr_segs, out_buf, out_len);
}

// Select the supported iterator / kernel layout. This is observation-only;
// unsupported kernel-internal iterator types are not userspace DNS sends.
static __always_inline int fill_dns_payload(struct msghdr *msg,
                                            __u8 *out_buf,
                                            __u32 *out_len)
{
    struct iov_iter *iter = &msg->msg_iter;
    __u32 type = BPF_CORE_READ(iter, iter_type);

    // 6.0+ may expose userspace sendmsg data as one ITER_UBUF buffer.
    if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
        type == bpf_core_enum_value(enum iter_type, ITER_UBUF))
        return fill_dns_payload_from_ubuf(iter, out_buf, out_len);

    // 5.15 userspace sendmsg commonly arrives as ITER_IOVEC; other iterator
    // types are kernel-internal paths and are outside DNS userspace capture.
    if (type != bpf_core_enum_value(enum iter_type, ITER_IOVEC))
        return -1;

    // 6.10+ renamed iov_iter.iov to __iov; older kernels use the legacy name.
    if (bpf_core_field_exists(iter->__iov))
        return fill_dns_payload_from_iovec_current(iter, out_buf, out_len);

    return fill_dns_payload_from_iovec_legacy(iter, out_buf, out_len);
}

// Prefer msg_name for sendto(); fall back to skc_dport for connected sockets.
// Returns host-order port and writes the IPv4 destination when available.
static __always_inline __u16 dns_msg_dport_v4(struct sock *sk,
                                              struct msghdr *msg,
                                              __u8 *daddr)
{
    void *name = BPF_CORE_READ(msg, msg_name);
    if (name) {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_kernel(&sin, sizeof(sin), name) == 0 &&
            sin.sin_family == AGENT_AF_INET) {
            __builtin_memcpy(daddr, &sin.sin_addr, 4);
            return bpf_ntohs(sin.sin_port);
        }
        return 0;
    }
    __be16 nbo = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __be32 sk_daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __builtin_memcpy(daddr, &sk_daddr, 4);
    return bpf_ntohs(nbo);
}

// IPv6 mirror of dns_msg_dport_v4. IPv4-mapped IPv6 keeps the same port field.
static __always_inline __u16 dns_msg_dport_v6(struct sock *sk,
                                              struct msghdr *msg,
                                              __u8 *daddr)
{
    void *name = BPF_CORE_READ(msg, msg_name);
    if (name) {
        struct sockaddr_in6 sin6 = {};
        if (bpf_probe_read_kernel(&sin6, sizeof(sin6), name) == 0 &&
            sin6.sin6_family == AGENT_AF_INET6) {
            __builtin_memcpy(daddr, &sin6.sin6_addr, 16);
            return bpf_ntohs(sin6.sin6_port);
        }
        return 0;
    }
    __be16 nbo = BPF_CORE_READ(sk, __sk_common.skc_dport);
    struct in6_addr v6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
    __builtin_memcpy(daddr, &v6, 16);
    return bpf_ntohs(nbo);
}

// Reserve and fill the common DNS sample header. Address arrays are zeroed
// because userspace logs both; payload is left untouched and bounded by
// payload_len. Avoid memset here for the same BPF backend reason as zero_*.
static __always_inline struct dns_sample *reserve_dns_sample(__u8 source,
                                                             __u8 family,
                                                             __u16 dport,
                                                             __u64 cgroup_id)
{
    struct dns_sample *sample = bpf_ringbuf_reserve(&events, sizeof(*sample), 0);
    if (!sample) {
        note_ringbuf_drop();
        return NULL;
    }
    sample->kind = SAMPLE_KIND_DNS;
    sample->source = source;
    sample->family = family;
    sample->_pad0 = 0;
    sample->dport = dport;
    sample->_pad1 = 0;
    sample->payload_len = 0;
    sample->ts_ns = bpf_ktime_get_ns();
    sample->cgroup_id = cgroup_id;
    sample->start_boottime = current_start_boottime();
    sample->tgid = current_tgid();
    sample->_pad2 = 0;
    *(volatile __u32 *)sample->daddr_v4 = 0;
    {
        volatile __u64 *v6_words = (volatile __u64 *)sample->daddr_v6;
        v6_words[0] = 0;
        v6_words[1] = 0;
    }
    return sample;
}

static __always_inline int submit_dns_query_v4(__u8 source, struct sock *sk,
                                               struct msghdr *msg,
                                               __u64 cgroup_id)
{
    __u8 daddr[4] = {};
    __u16 dport = dns_msg_dport_v4(sk, msg, daddr);
    if (dport != DNS_PORT)
        return 0;

    struct dns_sample *sample = reserve_dns_sample(source, AGENT_AF_INET,
                                                   dport, cgroup_id);
    if (!sample)
        return 0;
    __builtin_memcpy(sample->daddr_v4, daddr, 4);

    __u32 written = 0;
    if (fill_dns_payload(msg, sample->payload, &written) < 0) {
        bpf_ringbuf_discard(sample, 0);
        return 0;
    }
    sample->payload_len = written;
    bpf_ringbuf_submit(sample, 0);
    return 0;
}

static __always_inline int submit_dns_query_v6(__u8 source, struct sock *sk,
                                               struct msghdr *msg,
                                               __u64 cgroup_id)
{
    __u8 daddr[16] = {};
    __u16 dport = dns_msg_dport_v6(sk, msg, daddr);
    if (dport != DNS_PORT)
        return 0;

    struct dns_sample *sample = reserve_dns_sample(source, AGENT_AF_INET6,
                                                   dport, cgroup_id);
    if (!sample)
        return 0;
    __builtin_memcpy(sample->daddr_v6, daddr, 16);

    __u32 written = 0;
    if (fill_dns_payload(msg, sample->payload, &written) < 0) {
        bpf_ringbuf_discard(sample, 0);
        return 0;
    }
    sample->payload_len = written;
    bpf_ringbuf_submit(sample, 0);
    return 0;
}

// Keep the Varlink path in .rodata instead of spending BPF stack bytes.
static const char systemd_resolved_target_path[SYSTEMD_RESOLVED_VARLINK_PATH_LEN] =
    SYSTEMD_RESOLVED_VARLINK_PATH;
