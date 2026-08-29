# HTTP Uprobe Runtime

This chapter defines how cicd-sensor discovers HTTP client code, attaches
uprobes, emits `http_request` events, and reclaims links. Cleartext HTTP capture
at `tcp_sendmsg` produces the same event but does not use this runtime.

OpenSSL HTTP/1.x, nghttp2 HTTP/2, and Go `net/http` HTTPS capture are
implemented. All `http_request` capture remains disabled by default while the
bounded first-call stop and environment compatibility gates are evaluated.
Operators can always disable it with `--enable-http-request=false`. When
disabled, both the cleartext tap and the HTTP uprobe runtime are inactive.

## Purpose and limits

Network destination alone is not always enough to identify a malicious action.
An upload to `github.com`, for example, can use a legitimate domain while
sending credentials or artifacts to an attacker-controlled repository. A
`domain` event can also be absent when a process uses DNS over HTTPS, leaving
`network_connect` with only an IP address.

`http_request` adds the method, query-stripped path, host, capture source, and
calling process. These fields provide additional detection and investigation
points for operations that otherwise share the same destination.

There is no universal capture point for every HTTP implementation. Plaintext is
available at different functions, some binaries have no attachable symbol, and
HTTP/2 or HTTP/3 may encode a request before a generic write function sees it.
This runtime therefore expands coverage for selected, verified function paths;
it does not claim complete HTTP visibility. An absent `http_request` event does
not prove that no HTTP or network communication occurred.

## Runtime architecture

HTTP uprobes are part of the [eBPF Runtime](../ebpf-runtime.md). KernelIO owns
kernel-facing resources and one HTTP uprobe worker. JobRegistry owns Jobs.
KernelTracker owns tracked-cgroup and process tracking state, and attributes
decoded kernel events to Job IDs.

### Discovery and attachment phase

```mermaid
sequenceDiagram
    participant BPF as Linux kernel / BPF
    participant IO as KernelIO reader / stop controller
    participant W as KernelIO HTTP uprobe worker
    participant KT as KernelTracker

    BPF->>BPF: executable mapping: discovery-cache check
    BPF->>BPF: record stop lease and request SIGSTOP
    BPF->>IO: attach candidate through dedicated control ring buffer
    IO->>W: classify mapped ELF and attach targets
    W->>BPF: attach uprobe links and update discovery cache
    Note over W: owns attachedTargets and every link operation
    W-->>IO: release stop after attach work
    IO->>BPF: SIGCONT and stop-lease deletion

    Note over BPF,KT: Once-per-minute link-removal check (periodic reclaim)
    KT-->>W: active cgroup IDs
    W->>BPF: after two complete misses: close links and delete cache entries
```

Attach candidates remain inside KernelIO and never enter CEL evaluation. They
use the dedicated 1 MiB `http_uprobe_attach_candidates` ring buffer and KernelIO
reader. Normal `events` delivery, KernelTracker attribution, and CEL
backpressure therefore cannot place attach work behind the security-event
pipeline for a process that BPF has requested to stop. KernelTracker supplies
only the active cgroup IDs needed by the worker's once-per-minute reclaim pass.
Exact cache and lease identities and bounds are listed under
[Retained state](#retained-state).

### Event delivery phase

```mermaid
flowchart LR
    subgraph KERNEL["Linux kernel / BPF"]
        CALL["selected HTTP<br/>function call"]
        UPROBE["uprobe entry"]
        GATE["tracked cgroup gate"]
        PARSE["bounded parse<br/>and redaction"]
        RING[("events ring buffer<br/>http_request sample")]

        CALL --> UPROBE --> GATE --> PARSE --> RING
    end

    subgraph KIO["KernelIO"]
        READER["sample reader"]
    end

    subgraph KT["KernelTracker"]
        ATTRIBUTION["decode and<br/>Job attribution"]
    end

    subgraph JOB["Job"]
        EVALUATION["CEL evaluation<br/>and output"]
    end

    RING --> READER --> ATTRIBUTION --> EVALUATION
```

Once links are attached, request capture no longer passes through the HTTP
uprobe worker. Parsed event samples follow the normal KernelIO-to-KernelTracker
delivery path.

The worker serializes classification, attach, and reclaim on one goroutine, so
no other goroutine mutates its link registry.

The diagrams separate the attach control path from the request event path. The
detailed attach, stop, and reclaim rules appear below.

An uprobe link belongs to a mapped file, not to one PID or Job. Several
processes, Jobs, or containers can share the same file and link. Every HTTP
uprobe BPF entry therefore checks `tracked_cgroups` before parsing or emitting
an event.

## Discovery and first-call barrier

Discovery reacts whenever a process in a tracked cgroup installs a file-backed
executable mapping. This normally happens for the main executable and shared
libraries during process startup, but it also covers libraries mapped later
through `dlopen` or an equivalent path. It is not a process-start-only hook.

The mapping hook runs before userspace can execute code from that mapping, but
ELF classification and uprobe attachment require userspace work. With
notification alone, a short-lived client can call the selected function first.
Fresh-process experiments reproduced this race: some first HTTPS requests
completed before attachment and were missed.

### Attach lifecycle

```mermaid
flowchart LR
    MAP["new executable<br/>file mapping"]
    FILTER["BPF: scope check<br/>and file dedupe"]
    LEASE["reserve candidate<br/>record stop lease"]
    STOP["request SIGSTOP"]
    OPEN["open mapped ELF<br/>verify identity"]
    CLASSIFY["resolve selected<br/>C or Go function"]
    ATTACH["attach links"]
    RESUME["SIGCONT<br/>delete lease"]

    MAP --> FILTER --> LEASE --> STOP --> OPEN --> CLASSIFY --> ATTACH --> RESUME
```

The implemented lifecycle is:

1. BPF accepts only a file-backed executable mapping in a tracked cgroup that
   is absent from `http_uprobe_discovery_cache`.
2. BPF reserves the dedicated attach-candidate ring buffer, records a
   process-generation lease, and requests SIGSTOP before returning to
   userspace.
3. KernelIO opens a pidfd and starts a best-effort resume timer based on the BPF
   stop timestamp.
4. The worker waits for visible tasks to stop, classifies the mapped ELF, scans
   the process's other executable mappings, and attaches selected functions.
5. Completion, error, queue rejection, timeout, and shutdown all converge on
   SIGCONT and lease deletion.

A second mapping created under the same process lease is queued without sending
another SIGSTOP. The worker scan and explicit candidates can overlap safely
because file-level discovery deduplication makes repeated classification
harmless.

**Why accept this trade-off.** SIGSTOP is an unusual observation barrier and
would be a poor default for a latency-sensitive production service. cicd-sensor
observes short-lived CI/CD Jobs, where a bounded first-seen pause is easier to
accept, while a single outbound HTTP request can be the entire exfiltration
attempt. The design therefore prioritizes reliable first-request capture over
zero scheduling intervention.

The stop is still best-effort. The controller aims to resume around 500 ms after
the BPF stop request, but scheduler and attach-processing delays mean this is
not a real-time deadline. Timeout resumes the process even when attachment has
not finished.

### Stop safety and recovery

Stopping another process creates a failure mode that ordinary observation does
not have: the Agent can disappear after SIGSTOP but before SIGCONT. The pinned
`http_uprobe_stop_leases` map is therefore a recovery ledger, not a discovery
cache. BPF writes the lease before requesting SIGSTOP, and the map remains
available if the Agent is killed.

| Situation | Result and recovery |
| --- | --- |
| attach completes | The controller sends SIGCONT and deletes the lease. |
| classification error, queue rejection, or timeout | The same release path sends SIGCONT and deletes the lease. Attachment may remain incomplete. |
| clean Agent shutdown | KernelIO first detaches the mapping hook, resumes controller-owned stops, sweeps the pinned ledger for a hook invocation that was already in flight, then unpins the empty ledger. |
| Agent receives SIGKILL or crashes after SIGSTOP | No userspace cleanup can run. The workload can remain stopped until cicd-sensor starts again. On startup, before attaching the mapping hook, KernelIO opens the pinned ledger, verifies each `(tgid, start_boottime)` against `/proc/<pid>/stat`, sends SIGCONT to the matching process, and deletes the lease. If the Agent is not restarted, this recovery does not occur. |
| PID has exited or been reused before startup recovery | The process-generation check fails, so KernelIO deletes the stale lease without signaling the unrelated process. |
| another actor had already stopped the process | SIGSTOP has no sender ownership that SIGCONT can preserve. Normal completion, timeout, shutdown, or startup recovery can resume that externally stopped process. This ownership ambiguity is an accepted constraint of the CI runner deployment model. |

Startup recovery runs even when the new Agent starts with
`--enable-http-request=false`. After recovery, the disabled runtime unpins the
unused lease map and does not attach cleartext, discovery, or HTTP uprobe
programs. If recovery fails, Agent initialization fails before the mapping hook
is attached, so the runtime does not create additional stops while old leases
remain unresolved.

### Discovery timing and alternatives

Discovery design has two separate choices: **when** to look for a target and
**which trigger** starts that work. Process exec, file open, and executable
mapping often happen close together during startup, but they expose different
files and have different first-call guarantees.

| Mechanism | Status | Trigger | Coverage and first-call behavior |
| --- | --- | --- | --- |
| **startup process scan** | Not adopted | At Agent startup, scan userspace `/proc`. | Can inspect mappings that already exist, but only for scope that is known at startup. It does not cover later processes and is not a first-call barrier. |
| **process-start scan** | Not adopted | On a process-exec event, scan that PID. | Can see the main executable, but shared libraries can be mapped later by the dynamic loader. The process can also run before userspace classification finishes. |
| **fanotify permission mediation** | Not adopted | Intercept executable opens with `FAN_OPEN_EXEC_PERM`; ordinary shared-library opens require broad `FAN_OPEN_PERM` marks. | Can block an open while userspace decides, but broad marks also deliver unrelated opens before cgroup filtering and add queue, response, and mount-lifecycle failure modes. |
| **mapping notification without stop** | Not adopted | On an executable mapping during startup or later `dlopen`, run `fentry/uprobe_mmap`. | Covers the main executable, shared libraries, and later mappings without scanning. It does not pause the workload; fresh-process experiments reproduced missed first HTTPS requests. |
| **mapping notification + bounded stop** | Implemented; primary | On the same `fentry/uprobe_mmap` event, filter and deduplicate in BPF. | Normally keeps the process from reaching a selected function until its links are attached, providing reliable first-call capture. Stop-establishment failure or timeout can still resume before attachment completes. |
| **periodic process scan** | Not adopted | At each configured interval, scan current target processes and mappings. | Can catch up after missed discovery, but adds recurring scan cost and still cannot guarantee the first request. |

The bounded mapping stop reuses the existing hook, cache, worker, and ELF
classification path. It does not add a fanotify listener, separate daemon,
Job-owned stop state, or another process-scan loop. Startup, process-start, and
periodic scans are not currently planned.

## Classification and retained state

### Candidate processing

`fentry/uprobe_mmap` receives a completed VMA and its backing file. BPF emits an
attach candidate only when the VMA is executable and file-backed, the current
cgroup is tracked, and the file is absent from the discovery cache. One ELF can
create several executable VMAs, so deduplication uses file identity rather than
VMA range or process identity.

The candidate carries device, inode, ctime, VMA range, process generation, and
stop state. It contains no HTTP bytes or file content. BPF inserts the cache
entry before notification so unrelated mappings of the same file do not create
repeated userspace work.

The process is stopped only after ring-buffer reservation and lease insertion
succeed. Reservation failure removes the cache entry for a later retry. Lease
or SIGSTOP failure is reported as a stop-establishment error; classification
may continue asynchronously, but first-call capture is not guaranteed.

The worker handles each file serially:

1. Open it through `/proc/<pid>/map_files` and verify device, inode, and ctime.
   A changed mapping is ignored and not cached.
2. Look for selected C functions in `.symtab` and `.dynsym`. If none are found,
   try the Go pclntab resolver described in
   [Go net/http Uprobes](go-http-uprobes.md).
3. Attach selected symbols or resolved file offsets and store the links as one
   attached target.
4. Keep definitive non-targets in the discovery cache. On transient failure,
   remove the cache entry so a later mapping can retry.

### Retained state

| Owner | State | Meaning | Bound and removal |
| --- | --- | --- | --- |
| HTTP uprobe worker | `attachedTargets` | Link registry keyed by mapped-file identity. Each entry holds the classification key, links, and consecutive complete-miss count. | 4,096 files; reclaim removes an entry after two complete misses. |
| BPF and KernelIO | `http_uprobe_discovery_cache` | Notification-suppression cache keyed by device, inode, and ctime. It records files already queued, classified, or attached; it does not own links. | 65,536-entry LRU; transient failure and reclaim remove entries. Eviction only permits reclassification. |
| BPF and stop controller | `http_uprobe_stop_leases` | Pinned recovery ledger keyed by tgid and start boottime. It records a process that may require SIGCONT after normal completion, timeout, shutdown, or Agent restart. | 4,096-entry hash; every release path removes its entry. |

`attachedTargets` is the source of truth for links. Neither discovery-cache
eviction nor stop-lease deletion can close a link.

## Event capture and delivery

Attachment prepares a capture point; it does not emit an event. A later call to
an attached function enters the [event delivery phase](#event-delivery-phase)
shown above.

### Capture points

| Function | Protocol path | Input contract | Source |
| --- | --- | --- | --- |
| [`SSL_write`](https://docs.openssl.org/master/man3/SSL_write/) | OpenSSL HTTP/1.x | plaintext buffer is argument 2; length is argument 3 | `openssl` |
| [`SSL_write_ex`](https://docs.openssl.org/master/man3/SSL_write/) | OpenSSL HTTP/1.x | same input-buffer argument positions | `openssl` |
| [`nghttp2_submit_request`](https://nghttp2.org/documentation/nghttp2_submit_request.html) | nghttp2 HTTP/2 | `nghttp2_nv` array is argument 3; count is argument 4 | `nghttp2` |
| [`nghttp2_submit_request2`](https://nghttp2.org/documentation/nghttp2_submit_request2.html) | nghttp2 HTTP/2 | same relevant argument positions | `nghttp2` |
| [`net/http.(*Transport).roundTrip`](go-http-uprobes.md) | Go `net/http` HTTPS, HTTP/1.x and HTTP/2 | `*http.Request` is ABIInternal integer argument 2; stripped Go 1.18-1.27 binaries are resolved through pclntab | `go_net_http` |

Selected functions with the same argument and parsing contract share one BPF
entry. OpenSSL is read before encryption, nghttp2 before HPACK encoding, and Go
before protocol encoding. All paths produce the same event shape.

### Event and redaction contract

| Field | Value |
| --- | --- |
| `method` | request method, normalized to lowercase for rule evaluation |
| `path` | origin-form request path, with query excluded by BPF, then normalized to lowercase |
| `host` | HTTP/1.x `Host`, HTTP/2 `:authority`, or Go `Request.Host` / `URL.Host`, normalized to lowercase; a port can remain |
| `source` | `openssl`, `nghttp2`, or `go_net_http` |
| `process` | KernelTracker process snapshot for the caller |

Raw request bytes, query parameters, other headers, and bodies do not cross the
kernel boundary. This is the redaction invariant.

## Closing unused uprobe links

An attached uprobe link remains active until the Agent closes it. One process
exiting, a container being deleted, or a pathname being unlinked is not enough:
another tracked process can still map the same file. The Agent must therefore
check current mappings rather than tie a link to one PID, Job, pathname, or
cgroup.

Once per minute, KernelTracker sends an immutable snapshot of active cgroup IDs
to the worker. The worker resolves current processes and mappings, then compares
them with `attachedTargets`. This deletion check is the **reclaim pass**.

```mermaid
flowchart LR
    TICK["1 minute ticker"]
    IDS["active cgroup IDs"]
    PIDS["resolve cgroup paths<br/>and read cgroup.procs"]
    MAPS["read process maps"]
    COMPARE["compare attached<br/>file identities"]
    CACHE["delete discovery<br/>cache entry"]
    CLOSE["close links and<br/>remove target"]

    TICK --> IDS --> PIDS --> MAPS --> COMPARE
    COMPARE -->|"file missed by two complete scans"| CACHE --> CLOSE
```

| Scan result | Worker action |
| --- | --- |
| At least one tracked process still maps the file. | Keep the links and reset the file's missing-scan count. |
| A complete scan does not find the file. | Increment its missing-scan count. After two complete scans miss it, delete its discovery-cache entry, close its links, and remove it from `attachedTargets`. |
| The discovery-cache entry cannot be deleted. | Keep the links and target so the next reclaim pass can retry. |
| A cgroup, process, or mapping cannot be read. | Treat the scan as incomplete. Keep every link and leave missing-scan counts unchanged. |

The cgroup snapshot, process-map reads, and mapping notifications are not
atomic. A file attached after the snapshot can appear absent from that scan even
while it is mapped. Waiting for a second complete scan prevents this race from
closing a fresh link. An incomplete scan keeps all links because it cannot prove
that a file is unused.

The HTTP uprobe worker is the only component that attaches or closes links. It
closes every remaining link during normal shutdown.

## Coverage

Coverage is defined by an observed function path, not by a tool name. A client
is verified only when a reproducible real-client E2E produces the expected
source and request fields. `Not covered (verified)` means the same environment
was tested and did not call a selected function.

Verified rows below use GitHub-hosted Ubuntu 22.04, 24.04, and 26.04 preview on
x64 and arm64 unless noted otherwise.

| Workload | Status | Observed path |
| --- | --- | --- |
| curl over HTTPS HTTP/1.1 | Verified | `SSL_write` |
| Python `urllib.request`, requests, and pip over HTTPS HTTP/1.x | Verified | `SSL_write_ex` |
| Node and npm over HTTPS HTTP/1.x | Verified | `SSL_write` |
| wget over HTTPS HTTP/1.x | Verified on 22.04 and 24.04 | `SSL_write`; Ubuntu 26.04 preview uses GnuTLS and is not covered. |
| Git over HTTPS HTTP/1.x | Not covered (verified) | GitHub-hosted Ubuntu uses a GnuTLS-backed Git HTTP helper. |
| curl and Node over HTTPS HTTP/2 | Verified | selected nghttp2 request API |
| Git over HTTPS HTTP/2 | Verified | selected nghttp2 request API for default negotiation and explicit `http.version=HTTP/2` |
| GitHub CLI (`gh api`) | Verified | `net/http.(*Transport).roundTrip` |
| GitLab CLI (`glab`) | Not yet verified | Real-client E2E pending. |
| Java or rustls-based HTTPS | Not covered | Does not call a currently selected function. |
| Python `h2` / httpx HTTP/2 | Not covered | Does not use nghttp2 for request submission. |

## Operational controls and known limits

- `http_request` capture is disabled by default during rollout. Operators can
  keep every capture source disabled with `--enable-http-request=false` after
  the default changes.
- Disabled startup still performs stop-lease recovery from an earlier enabled
  Agent. It does not attach discovery, start the worker, stop new processes, or
  create dynamic uprobe links.
- The bounded stop reduces the first-call race but does not create a real-time
  guarantee. Timeout can resume the process before attachment completes.
- If the Agent is killed after SIGSTOP, the workload can remain stopped until
  the Agent restarts and processes the pinned recovery ledger. See
  [Stop safety and recovery](#stop-safety-and-recovery).
- The Agent can resume a process stopped earlier by another actor because
  SIGCONT cannot preserve SIGSTOP sender ownership. This is an accepted
  constraint of the CI runner deployment model.
- Discovery observes executable mappings created while the process is already
  in a tracked cgroup. Initial catch-up scanning, periodic attach backstop,
  moving an existing process into a tracked cgroup, and later
  `mprotect(PROT_EXEC)` are not current discovery paths.
- C library capture requires a selected function in `.symtab` or `.dynsym`. Go
  capture accepts only the pclntab layouts and ABI/object-layout range listed in
  [Go net/http Uprobes](go-http-uprobes.md).
- HTTP/1.x parsing starts at one write boundary. A split request line or `Host`
  outside the bounded prefix can be missed.
- HTTP/2 is visible only before HPACK in a selected nghttp2 API. Other HTTP/2
  implementations and HTTP/3/QUIC are not parsed.
- The nghttp2 parser examines at most 32 pseudo-headers and requires `:method`
  and an origin-form `:path`. Standard CONNECT has no `:path` and is not
  emitted; extended CONNECT can be emitted but `:protocol` is not exposed.
- The nghttp2 tap drops methods longer than 15 bytes and paths longer than 255
  bytes. A missing, invalid, or oversized `:authority` produces an empty host.
- Retries can produce duplicate events. Capture is not exactly once.
