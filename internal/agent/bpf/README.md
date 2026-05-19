# BPF Program Files

This directory keeps the handwritten BPF source, the `go generate` entrypoint,
vendored / generated headers, and the bpf2go output that ships in the agent
binary.

## Hand-edited files

- `program.bpf.c` — BPF object composition root and license declaration.
- `kernel_samples.h` — ringbuf sample ABI structs and kind constants.
- `maps.bpf.h` — BPF maps, globals, and map value types.
- `common_helpers.bpf.h` — shared hook primitives and macros.
- `cgroup_helpers.bpf.h` — cgroup identity and tracking helpers.
- `path_helpers.bpf.h` — bounded path helpers.
- `dns_helpers.bpf.h` — DNS payload extraction and emit helpers.
- `process_hooks.bpf.h` — process fork / exec hooks.
- `cgroup_hooks.bpf.h` — cgroup lifecycle hooks.
- `file_hooks.bpf.h` — file open and filesystem mutation hooks.
- `network_hooks.bpf.h` — network connect and AF_UNIX connect hooks.
- `dns_hooks.bpf.h` — DNS sendmsg hooks.
- `generate.go` — `go generate` entrypoint invoking bpf2go.
- `README.md` — this file.

## Generated artifacts (do not edit)

- `generated/bpf_program_bpfel.go`
- `generated/bpf_program_bpfel.o`

The agent intentionally ships only the `bpfel` object because supported Linux
targets are little-endian (`amd64` / `arm64`).

Regenerate with:

```bash
go generate ./internal/agent/bpf
```

## External headers

- `include/libbpf/`: vendored libbpf headers.
- `include/vmlinux/`: kernel BTF dump for BPF CO-RE.

Source and refresh procedure for both trees are documented in
`include/README.md`.

## Licensing

The repository as a whole is Apache-2.0 (top-level `LICENSE`).

`program.bpf.c` and the compiled `.o` files under `generated/` are
dual-licensed `GPL-2.0-only OR BSD-2-Clause`: the kernel BPF verifier requires
a GPL-compatible declaration to grant access to GPL-only helpers, and
BSD-2-Clause keeps the source redistributable alongside Apache-2.0. The
authoritative declaration lives in each source file's
`SPDX-License-Identifier` header.

Headers under `include/` carry their own SPDX identifiers; see
`include/README.md` for sources.
