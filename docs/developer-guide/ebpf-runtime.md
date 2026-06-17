# eBPF Runtime

The eBPF Runtime is the layer that observes CI/CD job process, network, file access, and domain access at the kernel level. Kernel baseline is Linux `5.15+`.

## Why cgroup v2 tracking

When monitoring CI/CD runtime, deciding **how much of the OS to observe** is the core design tradeoff.

| Approach | Strength | Weakness |
| --- | --- | --- |
| Watch the whole host | Few blind spots | Noisy: runner host, system daemons, unrelated workloads — hard to interpret in CI/CD context |
| Watch only the job's processes by PID lineage | Quiet | Misses work that goes through a container runtime or a host-side helper process |
| **cgroup v2 membership (cicd-sensor)** | Quiet for normal CI/CD activity, while still catching container workloads through staging promote | Cannot follow work that escapes into another host-side process; those escape patterns are handled as runtime events instead |

cicd-sensor uses cgroup v2. Kernel hooks check whether the current cgroup is in `tracked_cgroups` and fast-drop unrelated events. The userspace KernelTracker keeps a `cgroup_id -> JobIdentity` mirror and decides which job receives each EventRecord.

Process context is attached to events as a **fat-node snapshot** (`exec_path`, `argv`, `ancestors`). It is not walked at evaluation time. The source of truth for job membership is cgroup tracking, not process context.

```mermaid
flowchart LR
    JOB["CI/CD Job"]
    CG["tracked cgroups<br/>cgroup v2 IDs"]
    BPF["eBPF programs<br/>observe / fast drop"]
    RB["ringbuf samples"]
    KT["KernelTracker<br/>userspace mirror"]
    WORKER["Job event worker"]

    JOB --> CG
    CG --> BPF
    BPF --> RB
    RB --> KT
    KT -->|"EventRecord"| WORKER

    classDef cicdSensor fill:#ecfdf5,stroke:#0f766e,color:#134e4a,stroke-width:1.5px;
    class KT cicdSensor
```

## Tracking model

| Pattern | Trigger | Role |
| --- | --- | --- |
| cgroup membership | `cgroup_mkdir`, `cgroup_attach_task`, `cgroup_rmdir` | Tracks job-related cgroups through inheritance, migration, and removal |
| staging promote | Docker proxy + `cgroup_mkdir` | If the caller of a Docker create request belongs to a tracked job, bind the later container cgroup to that job |
| process context enrichment | `sched_process_fork`, `sched_process_exec`, `sched_process_exit` | Creates a fat node snapshot with `exec_path`, `argv`, and `ancestors` for `EventRecord.Process` |

When a CI/CD job starts a container through the host-side Docker socket, the actual container process may enter a separate cgroup created by dockerd, not a descendant cgroup of the job process. In that case, cgroup membership alone cannot track the container as part of the job.

The Docker proxy checks the peer process of the Docker create request and determines whether that process belongs to a tracked job cgroup. If it does, the proxy stages the basename of the container cgroup that will be created and associates it with the job. Later, when the kernel-side `cgroup_mkdir` hook observes the actual container cgroup creation, that staging entry is promoted and the container cgroup is added to the job's tracked cgroups.

## Event coverage

The eBPF Runtime handles both rule-facing events and internal tracking samples.

| Area | Representative hooks | Rule-facing event |
| --- | --- | --- |
| process | `sched_process_exec` | `process_exec` |
| cgroup tracking | `cgroup_mkdir`, `cgroup_attach_task`, `cgroup_rmdir` | internal tracking sample |
| network | `cgroup/connect4`, `cgroup/connect6` | `network_connect` |
| file | `security_file_open`, `security_inode_unlink`, `security_inode_rename`, `security_inode_link` | `file_open`, `file_remove`, `file_move`, `file_link` |
| domain | `udp_sendmsg`, `udpv6_sendmsg`, `tcp_sendmsg` | `domain` |
| unix socket | `unix_stream_connect`, `unix_dgram_connect` | `unix_socket_connect` |

`cgroup/connect4/6` is not attached per tracked cgroup. The agent attaches once to the cgroup v2 root detected at startup, and the program uses `tracked_cgroups` lookup to handle only target jobs.

`unix_stream_connect` / `unix_dgram_connect` observe AF_UNIX connects at the proto_ops entry points, so connects denied earlier by an LSM (AppArmor, SELinux, BPF LSM) are not observable.

## Kernel / userspace boundary

BPF map state is intentionally small. The kernel side only needs to answer two questions: whether the current cgroup should be observed, and whether a Docker cgroup basename has already been staged. Richer state such as JobIdentity and process context lives in the KernelTracker userspace mirror.

### BPF maps

| Map | Key | Role |
| --- | --- | --- |
| `tracked_cgroups` | cgroup ID | Lets BPF hooks decide on the fast path whether the current cgroup is in scope |
| `staging_map` | Docker cgroup basename | Lets the `cgroup_mkdir` hook detect cgroup creation staged by the Docker proxy |

`staging_map` does not contain JobIdentity. The kernel side only matches the basename; userspace mirror state knows which job it belongs to.

### KernelTracker userspace state

| State | Role |
| --- | --- |
| `jobByCgroup` | Maps cgroup ID to JobIdentity for attributing kernel samples to jobs |
| `cgroupsByJob` | Cleans up all cgroups belonging to a job when the job ends |
| `stagingByBasename` | Maps Docker cgroup basename to JobIdentity and promotes `staging_map` hits to jobs |
| `stagingByJob` | Cleans up staging entries for a job when the job ends |
| `processesByJob` / `processNode` | Holds process fat nodes and attaches `exec_path`, `argv`, and `ancestors` to EventRecord |

### EventRecord delivery pressure

KernelTracker owns the boundary between decoded kernel samples and each Job's event worker.
Each Job has a bounded `EventRecord` channel; the default capacity is 64k records.
The bound is intentional: a slow or blocked Job worker must not create unbounded memory growth in the agent.

`file_open` can be much higher volume than process, network, or domain events.
Repeated reads of the same file by the same process are common during package install, build, and runtime startup.
If those repeated records fill the per-Job channel, later `process_exec` or unique credential-like file reads can be dropped before rule evaluation sees them.

To protect the delivery path, KernelTracker suppresses repeated same-key `file_open` records before enqueueing them into the Job channel.
This is a delivery-pressure optimization, not a rule semantic change:

- the first successfully enqueued event for a key is preserved;
- unique paths are not collapsed;
- truncated, malformed, or incomplete `file_open` records are not suppressed;
- non-`file_open` event types are never deduplicated by this path.

The dedup key is explicit rather than a generic payload hash:

| Key field | Reason |
| --- | --- |
| process PID + start boottime | Distinguishes process lifetimes even when PIDs are reused |
| process executable path | Keeps same PID/start context readable when exec context changes |
| file path | Keeps unique file enumeration visible |
| read/write mode | Keeps read and write behavior separate |
| open flags | Keeps rule-visible open-flag differences separate |

The dedup state is per Job, loop-local to KernelTracker, and bounded.
It keeps up to 4096 file-open keys per Job; this is separate from the 64k per-Job EventRecord channel capacity.
It uses FIFO eviction rather than LRU so a hot repeated key does not refresh itself forever and evict newer unique keys.
The FIFO order is stored as a fixed-size ring buffer, so inserts remain O(1) after the per-Job key limit is reached.
KernelTracker records delivery diagnostics internally (`attempted`, `delivered`, `dropped`, `suppressed_duplicates`, and `max_queue_depth`) and logs a summary when a Job is removed if drops or suppression occurred.
Manager `runtime_event` output uses the same 64k queue capacity so the post-evaluation log path does not immediately become the next bottleneck; detection and summary outputs keep the smaller manager-output queue because they are not raw event streams.

## Implementation layout

| Path | Content |
| --- | --- |
| `internal/agent/bpf` | Hand-written eBPF C source, headers, and bpf2go-generated bindings / objects |
| `internal/agent/kerneltracker` | KernelTracker reactor, decoded sample domain, cgroup / process tracking |
| `internal/agent/kerneltracker/kernelio` | BPF object load, attach, ringbuf read, and map operations |
| `internal/agent/proxy/dockerd` | Registers staging basenames from Docker API responses |

`internal/agent/bpf` owns the eBPF assets, and `internal/agent/kerneltracker` owns the userspace reactor. Generated artifacts (`bpf2go` output) are not edited by hand — fix the C source or generator input.
