# HTTP Uprobe Runtime

cicd-sensor uses uprobes to observe HTTP requests before a userspace library
encrypts or encodes them. Coverage is defined by the library function that a
workload calls, not by a language, package manager, or executable name.

## Architecture

The HTTP uprobe worker is owned by KernelIO and runs as one owner goroutine.
Attach, reconciliation, and close operations are therefore serialized; the
worker is not pinned to one OS thread, but no second goroutine reads or mutates
its target state.

In this documentation, **eBPF Runtime** means the complete kernel-observation
layer: KernelTracker and KernelIO in Agent userspace plus the BPF programs,
maps, ring buffer, and uprobe attachments loaded into the Linux kernel. It is
an architectural term, not another Go component or goroutine.

The following diagram extracts the kernel-observation portion of the
[Agent architecture](../agent.md#architecture) and adds the HTTP-specific
worker and kernel resources.

```mermaid
flowchart LR
    subgraph ER["eBPF Runtime"]
        direction LR
        subgraph KR["Agent userspace"]
            direction LR
            KT["KernelTracker<br/>Job and cgroup ownership<br/>single owner loop"]

            subgraph KIO["KernelIO"]
                direction TB
                BIO["BPF load, map I/O,<br/>ringbuf reader"]
                WORKER["HTTP uprobe worker<br/>one owner goroutine"]
                STATE[("Worker-owned state<br/>attached targets and links")]
                WORKER -.->|"sole owner"| STATE
            end
        end

        subgraph KERNEL["Linux kernel"]
            direction TB
            ATTACH["HTTP uprobe attachments"]
            BPF["eBPF programs and ring buffer"]
            CACHE[("tracked cgroups,<br/>mapping dedup and non-target cache")]
            ATTACH -->|"invoke BPF entry"| BPF
            BPF <--> CACHE
        end
    end

    KT -->|"tracked cgroup map operations"| BIO
    BIO <-->|"load, attach, read"| BPF
    BIO -->|"mapping control sample"| WORKER
    BIO -->|"raw security samples"| KT
    KT -->|"active cgroup IDs"| WORKER
    WORKER -->|"attach or close"| ATTACH
```

KernelTracker remains the owner of Job and cgroup state. KernelIO owns
kernel-facing resources. The HTTP uprobe worker is a specialized KernelIO
lifecycle owner; it does not own Jobs or evaluate rules.

## Coverage status

Current library capture paths are:

| Protocol path | Status |
| --- | --- |
| OpenSSL HTTP/1.x through `SSL_write` / `SSL_write_ex` | Implemented; rollout disabled |
| HTTP/2 through `nghttp2_submit_request` / `nghttp2_submit_request2` | Implemented; rollout disabled |

Both paths use the existing `http_request` event. Raw request bytes, ordinary
headers, and bodies must not leave the kernel. HTTP uprobe rollout remains
disabled until environment compatibility and first-request timing are verified.

Implementation is split into two phases. **Phase 2a** provides executable-mapping
discovery for the OpenSSL and nghttp2 taps while keeping their event and reclaim
contracts. It is implemented and verified on arm64
Ubuntu 24.04 with Linux 6.8, but its asynchronous attach does not guarantee the
first request: isolated fresh-process runs captured curl 4/10 times and Python
`urllib.request` 10/10 times. Steady-state capture passes. **Phase 2b** adds
stripped Go binary resolution and Go `net/http` capture only after the Phase 2a
timing and supported-kernel gates are resolved.

## Runtime model

An uprobe associates a BPF program with a function offset in an ELF file. The
kernel runs that program when a process enters the function. cicd-sensor
attaches by mapped file and symbol, not by PID, so processes that map the same
file can share one attachment.

| Term | Meaning in cicd-sensor |
| --- | --- |
| target | One mapped executable file identified by device and inode. |
| uprobe link | The userspace handle for one target symbol. Closing it detaches that symbol. |
| attached target | One target and all of its links, owned by the HTTP uprobe worker. |
| non-target cache | A bounded BPF LRU map of files that define none of the selected symbols. It owns no links. |

The attachment can be reached by processes outside a CI Job because it belongs
to the mapped file. Every uprobe BPF program therefore checks
`tracked_cgroups` before parsing or emitting an event.

## Lifecycle

One worker in `internal/agent/kerneltracker/kernelio` owns all HTTP uprobe links
and classification state. It serially handles two inputs:

- an executable file mapping observed in a tracked cgroup;
- an active-cgroup snapshot from the periodic reconciliation timer.

### 1. Mapping-triggered attach

`fentry/uprobe_mmap` observes a completed file-backed executable mapping. The
BPF program rejects untracked cgroups, non-executable or anonymous mappings,
known non-target files, and duplicate process/file observations before emitting
a small control sample. It does not read the mapped file or resolve symbols.

```mermaid
flowchart LR
    P["Tracked process maps<br/>an executable file"]

    subgraph BPF["internal/agent/bpf"]
        direction TB
        M["fentry/uprobe_mmap"]
        F["VM_EXEC + file + tracked cgroup"]
        C["BPF negative cache<br/>and process/file dedup"]
        R["events ring buffer<br/>mapping control sample"]
        M --> F --> C --> R
    end

    subgraph KIO["internal/agent/kerneltracker/kernelio"]
        direction TB
        D["KernelIO ringbuf reader<br/>decode mapping control sample"]
        Q["bounded non-blocking queue"]
        W["httpUprobeDiscovery.run<br/>single worker"]
        O["open /proc/PID/map_files/range<br/>verify dev, inode and ctime"]
        A["resolve selected symbols<br/>attach links or cache non-target"]
        D --> Q --> W --> O --> A
    end

    P --> M
    R --> D
```

The worker handles each queued executable mapping serially:

| Classification result | Worker action |
| --- | --- |
| already attached | Keep the existing links. |
| present in the BPF non-target cache | Stop in the kernel before ringbuf emission. |
| at least one selected symbol attaches | Store the links as one attached target. |
| every selected symbol is absent | Add the classification key to the BPF non-target cache. |
| permission, I/O, identity mismatch, or another transient failure | Store nothing; a future process mapping the file can retry. |

The queue is non-blocking so discovery cannot stop kernel-sample intake. The
mapping sample is KernelIO control-plane input: the KernelIO ringbuf reader
decodes it and queues the worker without sending it to KernelTracker, Job
attribution, or CEL evaluation. The worker
opens the exact `map_files` range from the sample. If VMA merging removed that
range, it scans the same process once for the same device/inode and retries with
the current range. The final file descriptor must still match device, inode,
and ctime before classification. The worker reads the ELF symbol tables once
and passes only selected symbols defined by that file to cilium/ebpf. Undefined
imports, such as an executable referring to `SSL_write` in libssl, are not
attach targets; a file with no selected definitions is a definitive non-target.

The non-target cache is a 65,536-entry BPF LRU map keyed by device, inode, and
ctime. Process/file dedup is a separate BPF LRU map keyed by process start time,
TGID, and the same file classification key. The first avoids repeated userspace
classification; the second collapses multiple executable segments of one file
into one request.

### 2. Event delivery after attach

Attaching a link does not itself create an `http_request`. An event starts when
a tracked process later calls an attached function.

```mermaid
flowchart LR
    P["Tracked process<br/>calls selected function"]

    subgraph BPF["internal/agent/bpf"]
        direction TB
        U["uprobe entry<br/>OpenSSL or nghttp2"]
        G["tracked_cgroups gate"]
        H["http_helpers.bpf.h<br/>bounded parse and query removal"]
        R["events ring buffer<br/>http_request_sample"]
        U --> G --> H --> R
    end

    subgraph USERSPACE["Agent userspace delivery"]
        direction TB
        READ["kernelio<br/>raw sample reader"]
        DECODE["kerneltracker<br/>decodeKernelSample"]
        ATTR["kerneltracker<br/>attribute Job and create EventRecord"]
        READ --> DECODE --> ATTR
    end

    subgraph JOB["internal/agent/job"]
        EVAL["Job event worker<br/>CEL evaluation and output"]
    end

    P --> U
    R --> READ
    ATTR --> EVAL
```

The parser emits only method, query-stripped path, host, source, and process
identity. An untracked process reaches the same attached function but is dropped
at the cgroup gate before parsing.

#### Captured fields

`http_request` adds the HTTP operation to the network context. In particular,
`path` distinguishes requests to different APIs on the same otherwise legitimate
host, which cannot be determined from `domain` or `network_connect` alone.

| Field | Captured value |
| --- | --- |
| `method` | Request method, normalized to lowercase for rule evaluation. |
| `path` | Request path with the query removed in eBPF, then normalized to lowercase. |
| `host` | HTTP/1.x `Host` or HTTP/2 `:authority`, normalized to lowercase; a port can remain. |
| `source` | Capture path: `openssl` or `nghttp2`. |
| `process` | KernelTracker's process snapshot for the caller: executable, arguments, and ancestors. |

No query, other request header, or body is emitted. This is both the event
contract and the redaction boundary.

### 3. Reconcile and close

A link does not disappear when one process exits, and one target can be shared
by several Jobs or containers. Link lifetime therefore cannot follow one PID or
one Job. KernelTracker starts one reconciliation every minute; the worker scans
current mappings and closes targets that are no longer used by any tracked
process.

```mermaid
flowchart LR
    subgraph SCHEDULE["KernelTracker schedule"]
        direction TB
        T["Run<br/>1 minute ticker"]
        IDS["activeCgroupIDs"]
        Q["KernelIO<br/>QueueHTTPUprobeReconciliation"]
        T --> IDS --> Q
    end

    subgraph SCAN["KernelIO worker · liveness scan"]
        direction TB
        PATHS["cgroup ID to<br/>cgroupfs path"]
        PIDS["read<br/>cgroup.procs"]
        MAPS["scan<br/>/proc/PID/maps"]
        PATHS --> PIDS --> MAPS
    end

    subgraph DECIDE["KernelIO worker · reclaim decision"]
        direction TB
        OBS["observed mapped targets"]
        APPLY["reconcileTargets<br/>keep or close"]
        OBS --> APPLY
    end

    Q --> PATHS
    MAPS --> OBS
```

`reconcileTargets` applies three rules:

| Observation | Result |
| --- | --- |
| target is mapped by a tracked process | Reset its missing count. |
| target is absent from a complete scan | Record a first miss. Close the links only if the next complete scan also misses the target. |
| target is absent and a read failure could have hidden a mapping | Mark the scan incomplete; keep the links and the current missing count. |

Reconciliation observes liveness and closes stale targets. It does not classify
or attach files. The active-cgroup snapshot and process mappings are not read
atomically. For example, the worker can attach a newly mapped target after the
snapshot was taken; that older snapshot can miss the fresh target once. Closing
only after a second complete
missing observation prevents this one-scan race from detaching the new links.
An incomplete scan neither advances nor resets the missing count.

### Ownership

- The KernelTracker loop owns Job and cgroup tracking. It sends an immutable
  active-cgroup ID snapshot to KernelIO.
- The KernelIO ringbuf reader consumes mapping control samples itself and sends
  only security-event samples to KernelTracker. Neither component changes links.
- The HTTP uprobe worker exclusively owns attached targets, links, and all
  userspace updates to the non-target cache. Attach, cache updates, and close run
  serially on this goroutine, so they do not require a mutex.
- On shutdown, the worker closes every remaining link.

## Coverage contract

A function is selected only when it exposes method, path, and host before
encryption or protocol encoding; has a stable public argument ABI and a symbol
resolvable from `.symtab` or `.dynsym`; is used by a relevant CI workload; and
can reuse the existing event and lifecycle without weakening redaction. A client
is documented as verified only after a privileged real-client E2E proves the
call path.

### Selected functions

| Function | Status | Reason | Verification |
| --- | --- | --- | --- |
| [`SSL_write`](https://docs.openssl.org/master/man3/SSL_write/) | Implemented; rollout disabled | OpenSSL HTTP/1.x plaintext buffer is argument 2 and length is argument 3. | curl and wget HTTP/1.1 E2E |
| [`SSL_write_ex`](https://docs.openssl.org/master/man3/SSL_write/) | Implemented; rollout disabled | Same relevant argument positions; required by the observed Python path. | Python `urllib.request`, requests, and pip E2E |
| [`nghttp2_submit_request`](https://nghttp2.org/documentation/nghttp2_submit_request.html) | Implemented; rollout disabled | Exposes `nghttp2_nv` before HPACK; `nva` is argument 3 and `nvlen` is argument 4. | curl, Node, and Git HTTP/2 E2E |
| [`nghttp2_submit_request2`](https://nghttp2.org/documentation/nghttp2_submit_request2.html) | Implemented; rollout disabled | Same relevant argument positions; complements `submit_request` across versions. | Attach integration; real clients may use either selected symbol |

One BPF entry is shared when selected symbols have the same argument and parse
contract.

### Workload status

Each verified status has a reproducible real-client E2E on GitHub-hosted
Ubuntu. `Not covered (verified)` means that the same E2E confirmed the absence
of an OpenSSL `http_request` event for that runner image.

| Workload | Status | Verification |
| --- | --- | --- |
| curl over HTTPS HTTP/1.1 | Verified | GitHub-hosted Ubuntu 22.04, 24.04, and 26.04 preview on x64 and arm64; observes `SSL_write`. |
| Python `urllib.request` over HTTPS HTTP/1.1 | Verified | GitHub-hosted Ubuntu 22.04, 24.04, and 26.04 preview on x64 and arm64; observes `SSL_write_ex`. |
| Python requests over HTTPS HTTP/1.x | Verified | GitHub-hosted Ubuntu 22.04, 24.04, and 26.04 preview on x64 and arm64; observes `SSL_write_ex`. |
| pip over HTTPS | Verified | GitHub-hosted Ubuntu 22.04, 24.04, and 26.04 preview on x64 and arm64; observes `SSL_write_ex`. |
| Node over HTTPS HTTP/1.x | Verified | GitHub-hosted Ubuntu 22.04, 24.04, and 26.04 preview on x64 and arm64; observes `SSL_write`. |
| npm over HTTPS | Verified | GitHub-hosted Ubuntu 22.04, 24.04, and 26.04 preview on x64 and arm64 through Node's `SSL_write` path. |
| wget over HTTPS HTTP/1.x | Verified on 22.04 and 24.04 | GitHub-hosted x64 and arm64 observe `SSL_write`; Ubuntu 26.04 preview uses GnuTLS and is not covered. |
| Git over HTTPS HTTP/1.x | Not covered (verified) | GitHub-hosted Ubuntu 22.04, 24.04, and 26.04 preview on x64 and arm64 use a GnuTLS-backed Git HTTP helper. |
| curl over HTTPS HTTP/2 | Verified | GitHub-hosted Ubuntu real-client E2E; observes a selected nghttp2 request API. |
| Node over HTTPS HTTP/2 | Verified | GitHub-hosted Ubuntu real-client E2E; observes a selected nghttp2 request API. |
| Git over HTTPS HTTP/2 | Verified | GitHub-hosted Ubuntu real-client E2E covers both libcurl's default negotiation and an explicit `http.version=HTTP/2`; both observe a selected nghttp2 request API independently of the TLS backend. |
| Go, Java, or rustls-based HTTPS | Not covered | Does not call a selected function. |
| Python `h2` / httpx HTTP/2 | Not covered | Does not use nghttp2 for request submission. |

## Known limits

- Discovery only observes executable file mappings made while the process is in
  a tracked cgroup. Phase 2a does not scan mappings that predate tracking, add a
  catch-up path for a process moved into a tracked cgroup, or treat periodic
  reclaim as an attach backstop.
- A mapping made executable only through a later `mprotect(PROT_EXEC)` is not a
  Phase 2a discovery contract.
- BPF and `fstat` file identities must match exactly. A mismatch is treated as
  a mapping race: the worker neither attaches nor negative-caches the file.
- A full 4,096-entry userspace mapping queue drops that mapping request rather
  than blocking ringbuf intake. A different process generation mapping the same
  file can retry; the dropped request has no same-process recovery guarantee.
- The worker refuses a new target when 4,096 mapped files are already attached.
  It never evicts a live target; reclaim must free capacity before a later
  mapping can retry.
- Mapping notification precedes the selected library call, but userspace must
  still open, classify, and attach the target asynchronously. The first call can
  therefore race ahead of attachment; this currently blocks rollout by default.

- Only calls through the selected library functions are visible. HTTPS through
  Go `crypto/tls`, Java JSSE, Rust rustls, Python `h2`, a non-nghttp2 HTTP/2
  stack, or an unverified OpenSSL-like fork does not expose request fields to
  these uprobes.
- Static linking is not itself unsupported. A dynamically or statically linked
  target is attachable only when the selected function can be resolved from its
  `.symtab` or `.dynsym`. A stripped static binary without that symbol is not
  captured.
- HTTP/1.x parsing starts at one write boundary. Split request lines or a `Host`
  outside the bounded prefix can be missed.
- HTTP/2 is visible only before HPACK in a selected nghttp2 API. Other HTTP/2
  implementations and HTTP/3/QUIC are not parsed.
- The nghttp2 parser examines at most the first 32 pseudo-headers and requires
  both `:method` and an origin-form `:path`. Standard HTTP/2 CONNECT creates a
  tunnel on one stream and omits `:path`, so it is not emitted. Extended CONNECT
  includes `:path` and can be emitted, but the event does not expose `:protocol`.
- The nghttp2 tap does not emit a request whose method exceeds 15 bytes or whose
  path exceeds 255 bytes. A missing, invalid, or oversized `:authority` produces
  an event with an empty `host`.
- Retries can produce duplicate events. Capture is not exactly once.
- Absence of `http_request` is not proof that no egress occurred. Rules should
  retain `network_connect` coverage; `domain` can also be absent when name
  resolution uses an encrypted path such as DNS over HTTPS.
