// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// One temporary normalization request, owned by the serial HTTP worker.
struct http_uprobe_control_request { __u64 nonce; };
struct http_uprobe_control_result {
    __u64 nonce;
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
    __uint(max_entries, 1);
    __type(key, __u64);
    __type(value, struct http_uprobe_control_result);
} http_uprobe_control_results SEC(".maps");
