# Agent Architecture

The Agent is the central component that connects CI/CD job lifecycle with runtime events.

One agent process runs on one host and can observe multiple CI/CD jobs at the same time.
Kernel-side observation is handled with eBPF. Job lifecycle and rule evaluation are handled in userspace.

## Architecture

```mermaid
flowchart TB
    START["host start / project start"]
    PROXY["dockerd proxy"]

    subgraph A["Agent"]
        direction TB
        L["Listener<br/>(Unix socket)"]

        subgraph JR["JobRegistry"]
            direction TB
            subgraph JOBS["Jobs"]
                direction TB
                EVAL["Evaluation"]
                SCOPE["Scope<br/>host / project"]
            end
        end

        subgraph KR["Kernel Runtime"]
            direction TB
            KT["KernelTracker<br/>Job state management<br/>(cgroup / process tracking)"]
            EBPF["eBPF Runtime"]
            KIO["KernelIO"]
            KT --> EBPF
            EBPF -->|"map operations"| KIO
            KIO -->|"decoded samples"| KT
        end

        subgraph OUT["Outputs"]
            direction TB
            LOGS["Job logs"]
            RESULT["Project result"]
        end
    end

    K["Kernel"]

    START --> L
    PROXY --> L
    L --> JOBS
    KT -->|"EventRecord"| EVAL
    EVAL --> SCOPE
    JR -->|"tracking commands"| KT
    KIO <-->|"eBPF maps / ringbuf"| K
    SCOPE --> LOGS
    SCOPE --> RESULT

```

This diagram is the reference point for reading the Agent implementation.
`host start`, `project start`, and dockerd proxy staging requests enter the Agent through the Listener over a Unix socket.
JobRegistry issues tracking commands to the Kernel Runtime.
Scope owns rule, summary, and output state, but it does not operate the Kernel Runtime directly.

## Subsystems

| Subsystem | Responsibility |
| --- | --- |
| Agent | Top-level orchestrator for Listener, JobRegistry, KernelTracker, and shutdown |
| Listener | Receives start / staging requests over the Unix socket and handles provider routes and peer credentials |
| JobRegistry | Handles job registration, host / project scope attachment, KernelTracker primitive composition, and finalize |
| Jobs / Scope | Handles per-job event workers, rule evaluation, and scope-local summaries / outputs |
| KernelTracker / eBPF Runtime | Handles cgroup / process tracking, kernel sample decoding, and EventRecord attribution |
| Outputs | Holds runtime summaries used as inputs for job logs, project results, reports, and attestations |

## Provider Flow

| Provider | Runner | Start entrypoint | cgroup seed |
| --- | --- | --- | --- |
| GitHub Actions | GitHub-hosted runner | `/v1/github/project/start` | cgroup of the project start peer PID |
| GitHub Actions | Self-hosted Machine Runner | `/v1/github/host/start` | cgroup of the hook peer PID |
| GitLab CI/CD | Self-hosted Container Executor | `/v1/gitlab/staging/put` -> lazy `/v1/gitlab/host/start` | Docker label evidence and staging promote |
| GitHub ARC / GitLab Kubernetes Executor | Planned | TBD | NRI / Pod metadata and similar options are under consideration |

The agent process selects one provider at startup.
The Listener mounts either `/v1/github/*` or `/v1/gitlab/*`, not both.

## KernelTracker Primitives

Job tracking is expressed by JobRegistry composing KernelTracker primitives.

| Primitive | Meaning |
| --- | --- |
| `RegisterJob(jobID)` | Creates userspace job state and a per-job event channel. Does not touch BPF maps. |
| `BindProcessCgroupToJob(jobID, pid)` | Resolves the PID cgroup and adds it to `tracked_cgroups`. |
| `StageCgroupBasenameForJob(basename, jobID)` | Stages a Docker cgroup basename. |
| `RemoveJob(jobID)` | Cleans up job state, cgroup bindings, staging entries, and process context. |

`RegisterJob` and cgroup binding are separate operations.
GitHub can resolve the cgroup from the peer PID at start time, so it uses `RegisterJob + BindProcessCgroupToJob`.
GitLab Container Executor registers a job from label identity evidence and waits for a later staging promote.

## Design Notes

- Job membership is determined by cgroup tracking. Process context is a fat node snapshot with `exec_path` / `argv` / `ancestors`; it is not used as the job boundary.
- KernelTracker state is owned exclusively by its loop goroutine. `jobTrackingState` is not published externally.
- Listener stays as the delivery layer. Provider differences are contained in handlers and JobRegistry primitive composition.
- Output runtime is scope-local. Host / project output queues are not hoisted into JobRegistry.
- JobRegistry owns lifecycle. It is not on the hot path for event routing.

For kernel-side observation details, see [eBPF Runtime](ebpf-runtime.md).
For the rule authoring surface, see [Rules](../user-guide/rules.md). For the internal implementation, see [Rule Engine](rule-engine.md).
