// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#pragma once

// cgroup_helpers.bpf.h — cgroup identity helpers.

static __always_inline __u8 cgroup_is_tracked(__u64 cgroup_id)
{
    // tracked_cgroups is the kernel-side source of truth for event filtering.
    __u8 *value = bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id);
    if (value)
        return 1;
    return 0;
}

static __always_inline __u64 cgroup_id_from_cgroup(struct cgroup *cgrp)
{
    // CO-RE tracks both fields, so layout drift in either hop is handled.
    return BPF_CORE_READ(cgrp, kn, id);
}

// 5.15–6.4 used cgroup.ancestor_ids[]; 6.5+ uses cgroup.ancestors[].
// This shadow keeps the old field discoverable when compiling with newer BTF.
// preserve_access_index forces CO-RE relocations for the shadow field.
struct cgroup___legacy {
    __u64 ancestor_ids[16];
} __attribute__((preserve_access_index));

// Return parent kernfs id, or 0 for root/unresolved. Avoid kn->parent: that
// layout has diverged across 6.x, while cgroup.level + ancestors is stable
// enough and can be selected with CO-RE at load time.
static __always_inline __u64 parent_cgroup_id_from_cgroup(struct cgroup *cgrp)
{
    int level;
    __u64 parent_id = 0;

    level = BPF_CORE_READ(cgrp, level);
    if (level <= 0 || level > 15)
        return 0;

    // Cast NULL only to name the legacy field for CO-RE existence checking.
    if (bpf_core_field_exists(((struct cgroup___legacy *)0)->ancestor_ids)) {
        // 5.15–6.4: ancestor_ids[] directly stores kernfs ids.
        struct cgroup___legacy *legacy = (struct cgroup___legacy *)cgrp;

        // Unroll so the runtime level selects among verifier-friendly fixed indexes.
#pragma unroll
        for (int i = 0; i < 16; i++) {
            if (i == level - 1) {
                parent_id = BPF_CORE_READ(legacy, ancestor_ids[i]);
                break;
            }
        }
        return parent_id;
    }

    // 6.5+: ancestors[] stores cgroup pointers; chase once to kn->id.
    struct cgroup *parent_cgrp = NULL;

    // Unroll so the runtime level selects among verifier-friendly fixed indexes.
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i == level - 1) {
            parent_cgrp = BPF_CORE_READ(cgrp, ancestors[i]);
            break;
        }
    }

    if (!parent_cgrp)
        return 0;

    parent_id = BPF_CORE_READ(parent_cgrp, kn, id);
    return parent_id;
}
