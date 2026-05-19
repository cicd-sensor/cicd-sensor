/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_ENDIAN__
#define __BPF_ENDIAN__

/*
 * Bundled from libbpf's bpf_endian.h. Keep this header local so go generate
 * does not depend on distro-specific kernel header packages being installed on
 * the build VM.
 */

#define ___bpf_mvb(x, b, n, m) ((__u##b)(x) << (b - (n + 1) * 8) >> (b - 8) << (m * 8))

#define ___bpf_swab16(x) ((__u16)(          \
		      ___bpf_mvb(x, 16, 0, 1) | \
		      ___bpf_mvb(x, 16, 1, 0)))

#define ___bpf_swab32(x) ((__u32)(          \
		      ___bpf_mvb(x, 32, 0, 3) | \
		      ___bpf_mvb(x, 32, 1, 2) | \
		      ___bpf_mvb(x, 32, 2, 1) | \
		      ___bpf_mvb(x, 32, 3, 0)))

#define ___bpf_swab64(x) ((__u64)(          \
		      ___bpf_mvb(x, 64, 0, 7) | \
		      ___bpf_mvb(x, 64, 1, 6) | \
		      ___bpf_mvb(x, 64, 2, 5) | \
		      ___bpf_mvb(x, 64, 3, 4) | \
		      ___bpf_mvb(x, 64, 4, 3) | \
		      ___bpf_mvb(x, 64, 5, 2) | \
		      ___bpf_mvb(x, 64, 6, 1) | \
		      ___bpf_mvb(x, 64, 7, 0)))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohs(x)			__builtin_bswap16(x)
# define __bpf_htons(x)			__builtin_bswap16(x)
# define __bpf_ntohl(x)			__builtin_bswap32(x)
# define __bpf_htonl(x)			__builtin_bswap32(x)
# define __bpf_cpu_to_be64(x)		__builtin_bswap64(x)
# define __bpf_be64_to_cpu(x)		__builtin_bswap64(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohs(x)			(x)
# define __bpf_htons(x)			(x)
# define __bpf_ntohl(x)			(x)
# define __bpf_htonl(x)			(x)
# define __bpf_cpu_to_be64(x)		(x)
# define __bpf_be64_to_cpu(x)		(x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_ntohs(x)				__bpf_ntohs(x)
#define bpf_htons(x)				__bpf_htons(x)
#define bpf_ntohl(x)				__bpf_ntohl(x)
#define bpf_htonl(x)				__bpf_htonl(x)
#define bpf_cpu_to_be64(x)			__bpf_cpu_to_be64(x)
#define bpf_be64_to_cpu(x)			__bpf_be64_to_cpu(x)

#endif /* __BPF_ENDIAN__ */
