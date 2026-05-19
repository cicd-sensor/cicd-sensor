//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "include/vmlinux/vmlinux.h"
#include "include/libbpf/bpf_core_read.h"
#include "include/libbpf/bpf_endian.h"
#include "include/libbpf/bpf_helpers.h"
#include "include/libbpf/bpf_tracing.h"

#include "kernel_samples.h"
#include "maps.bpf.h"
#include "common_helpers.bpf.h"
#include "cgroup_helpers.bpf.h"
#include "path_helpers.bpf.h"
#include "dns_helpers.bpf.h"
#include "process_hooks.bpf.h"
#include "cgroup_hooks.bpf.h"
#include "file_hooks.bpf.h"
#include "network_hooks.bpf.h"
#include "dns_hooks.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
