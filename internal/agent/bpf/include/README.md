# External BPF Include Files

This directory contains external headers used to build `program.bpf.c`. Both
trees are vendored so `go generate` does not depend on distro-specific kernel
header packages being installed on the build VM.

## libbpf

- `libbpf/`: small set of libbpf headers vendored from libbpf upstream
  (<https://github.com/libbpf/libbpf>, `src/` directory). Files:
  - `bpf_helpers.h`, `bpf_core_read.h`, `bpf_endian.h`, `bpf_tracing.h` —
    copied verbatim from `libbpf/src/`.
  - `bpf_helper_defs.h` — auto-generated upstream from the kernel UAPI
    `bpf.h` via `scripts/bpf_doc.py`; vendored as a snapshot.

Keep upstream `SPDX-License-Identifier` comments intact when refreshing. When
updating, record the libbpf commit hash (or release tag) in the commit message
so future readers can diff against the same upstream snapshot.

## vmlinux.h

- `vmlinux/`: kernel type definitions for BPF CO-RE (Compile Once - Run
  Everywhere).

### Structure

- `vmlinux/vmlinux_<kernel-version>.h`: versioned header generated from a
  specific kernel's BTF dump.
- `vmlinux/vmlinux.h`: symlink pointing to the currently active versioned file.

### Generation

Run on a Debian x64 (amd64) host matching the target kernel version:

```sh
sudo apt update && sudo apt install -y bpftool
/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux/vmlinux_$(uname -r | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+').h
```

Then re-point the stable symlink:

```sh
ln -sf vmlinux_<new-version>.h vmlinux/vmlinux.h
```
