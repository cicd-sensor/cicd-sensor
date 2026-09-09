// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

#define HTTP_UPROBE_CONTROL_NORMALIZE 1
#define HTTP_UPROBE_CONTROL_SCAN 3
#define HTTP_UPROBE_CONTROL_MAX_MAPPINGS 256

// Temporary worker control only: not a second classifier/cache/registry.
// The single worker locks its OS thread and uses pid_tgid + nonce + operation.
struct http_uprobe_control_request {
    __u64 nonce;
    __u32 operation;
    __u32 pid;
    __u32 count;
    __u32 overflow;
};
struct http_uprobe_control_result {
    __u64 nonce;
    __u64 start;
    __u64 end;
    struct file_classification_key file;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u64);
    __type(value, struct http_uprobe_control_request);
} http_uprobe_control_requests SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HTTP_UPROBE_CONTROL_MAX_MAPPINGS);
    __type(key, __u64);
    __type(value, struct http_uprobe_control_result);
} http_uprobe_control_results SEC(".maps");
