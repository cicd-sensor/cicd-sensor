package bpf

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -mcpu=v3" -target bpfel -tags linux -go-package bpf -output-dir generated -output-stem bpf_program -type fork_sample -type cgroup_mkdir_sample -type cgroup_attach_sample -type cgroup_rmdir_sample -type exec_sample -type net_v4_sample -type net_v6_sample -type file_open_sample -type file_remove_sample -type file_move_sample -type file_link_sample -type dns_sample -type unix_socket_connect_sample -type staging_value BPFProgram program.bpf.c -- -I. -Iinclude
