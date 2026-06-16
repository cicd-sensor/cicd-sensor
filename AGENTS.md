# Repo Instructions

cicd-sensor is an eBPF-powered CI/CD runtime security sensor.
The source of truth for design is `docs/`.

## AI agent workflow

This repo is developed through collaborative engineering, not autonomous "vibe coding".

AI agents should first investigate the code, docs, runtime behavior, and tradeoffs; then help write down the design or plan; then implement the agreed change. Do not skip directly from a rough idea to a finished PR.

Before changing external state such as creating, closing, reopening, or merging GitHub Issues / PRs, pushing branches, or publishing releases, show the exact target and proposed content, then wait for explicit approval.

Use ignored `work_docs/` for local temporary design drafts, progress notes, investigation logs, and result reports. Do not place local-only working notes at the repository root.

## What to read first

- `docs/index.md` — project goal and supported platforms
- `docs/user-guide/overview.md` — runner environments and usage models
- `docs/developer-guide/overview.md` — repository layout and subsystem reading order
- `docs/developer-guide/agent.md` — Job / Scope / JobRegistry / KernelTracker model
- `docs/developer-guide/agent-ownership-boundaries.md` — Agent / JobRegistry / Job / JobScopeState ownership rules and per-Job evaluation rationale
- `docs/developer-guide/ebpf-runtime.md` — cgroup v2 tracking, BPF map boundary, eBPF code style and contribution contract
- `docs/developer-guide/manager.md` — config and log delivery boundary
- `docs/developer-guide/rule-engine.md` — RuleSet / RuleModifier / CEL flow

## Detailed rules

The files below add detail that only applies when touching specific paths. **They apply to any AI coding agent working in this repo — Claude Code, Codex, Gemini, or otherwise. The `.claude/` directory is only there because Claude Code auto-loads from that path; the contents are not Claude-specific.** Read the relevant one before changing code in that area.

| File | Apply when |
| --- | --- |
| `.claude/rules/10-code.md` | Touching `**/*.go`, `go.mod`, `go.sum`. Go baseline, tooling, style, comments. |
| `.claude/rules/20-testing.md` | Writing or reviewing tests. Required test-case table and coverage-perspective table. |
| `.claude/rules/30-cel-rules.md` | Touching `rules/**`, `internal/rule/**`. RuleSet / RuleModifier schema, CEL surface, event-type sources. |
| `.claude/rules/40-supply-chain.md` | Touching `.github/**`, `.gitlab-ci.yml`, Dependabot, or Renovate config. SHA pinning and cooldown. |
| `.claude/rules/50-design-docs.md` | Writing or updating local Design Docs for large feature additions or substantial behavior changes. |

## Build and test

- `make build` — build agent + manager binaries (Linux).
- `make test` — run unit tests.
- `go test -race ./...` — race detector (required for concurrency changes).
- `make check` — `generate` + `test` + `rules-validate` + `rules-bundle-validate` + `diff-check` (the gate this repo uses before commit).
- `make integration` / `make bpf-integration` — integration suites (need privileges; may require Linux).
- `make rules-validate` — validate baseline rule YAML.
- `make generate` — regenerate protobuf and bpf2go output (run after touching `proto/` or BPF C sources). BPF compilation runs through Docker, so macOS / Windows hosts work as long as Docker is available.

## Repository layout

| Path | Role |
| --- | --- |
| `cmd/cicd-sensor` | Agent CLI |
| `cmd/cicd-sensor-manager` | Manager server |
| `cmd/cicd-sensorctl` | Report / attestation / rule validation CLI |
| `internal/agent` | Agent runtime (Listener, JobRegistry, Job, Scope, KernelTracker) |
| `internal/rule` | RuleSet / RuleModifier schema, resolution, CEL compile and evaluate |
| `internal/manager` | Config service, collector ingest, output routing |
| `internal/ctl` | Report and attestation generation |
| `proto/` | Connect / protobuf wire schema |
| `rules/` | Baseline rule YAML |
| `docs/` | Design source of truth (mdbook published from `cicd-sensor.github.io`) |

## Agent components

The Agent is built from several components, each owning a different boundary. Before writing code, identify which component owns the state, lifecycle, or interface you are touching. Do not let responsibilities leak across components.

| Component | Owns |
| --- | --- |
| `Agent` | Top-level process orchestrator. Owns provider/runner selection, socket lifecycles, manager clients, host config cache startup, and shutdown. |
| `Listener` | Unix-socket HTTP entrypoint. Owns provider routes, peer credentials, request trust checks, and dispatch into JobRegistry. |
| `NRI observer` | Separate `cicd-sensor nri` process. Observes containerd NRI events and sends Kubernetes staging requests to the Agent. |
| `ManagerClient / host config cache` | Manager config fetch boundary and cached host config for Kubernetes host paths. Does not own Jobs or KernelTracker state. |
| `JobRegistry` | Active jobs catalog and KernelTracker binding. Creates scope state, composes tracking primitives, and finalizes Jobs. |
| `Job` | One CI/CD job's lifecycle, identity, and event worker. |
| `JobScopeState` | Per-scope state for one Job — one host instance and / or one project instance per Job. Holds the Job's `RuleSets`, `RuleModifiers`, `OutputSettings`, and scope-local manager output config. |
| `Host scope` | The configuration surface owned by the runner host operator (the platform team installing cicd-sensor on the runner). It arrives via `host start` from a runner hook, and is used when the host enforces a baseline across every job on the runner — typically on self-hosted runners. |
| `Project scope` | The configuration surface owned by the project / repository operator (the team writing the CI workflow). It arrives via `project start` from the cicd-sensor-action (or equivalent), and lets each workflow bring its own rules and outputs — typically on GitHub-hosted runners. |
| `KernelTracker` | Userspace cgroup / process tracking, decoded sample domain, and EventRecord attribution. |
| `KernelIO` | BPF object load, attach, ringbuf read, and map operations. |
| `Docker proxy` | Mediates dockerd API and stages container cgroup basenames so jobs can track containers created through the host Docker socket. |
| `GitHub Kubernetes hooks` | Runner-side integration, not Agent-owned state. Supplies GitHub job identity to the Agent and, in ARC Kubernetes mode, to workflow Pods for NRI staging. |
| `Outputs` | Per-scope runtime summaries used for job logs, project results, reports, and attestations. |

A single Job may carry one scope or both. Each scope owns its own rules, evaluation state, and outputs, and the two are isolated: neither operator can read or override the other's rules, and their outputs are emitted separately. This is the security boundary of the agent — see `docs/developer-guide/agent.md` for the conceptual model and `docs/developer-guide/agent-ownership-boundaries.md` for the implementation ownership rules. For the kernel-side model, see `docs/developer-guide/ebpf-runtime.md`.

Host scope and project scope are internal Agent implementation boundaries. User-facing docs should describe the user-visible deployment path and configuration owner instead: installed runner, GitHub Action, project-local config, or manager config. GitHub Action can run with `manager-url`, so do not imply that Action configuration and manager configuration are mutually exclusive. Do not expose host/project scope mechanics in user docs unless the page is specifically explaining Agent architecture or a log field that uses scope to distinguish emitted records.

## Commits

- Conventional Commits. English. One-line title.
- No multi-paragraph body unless the change needs it.
- No `Claude`, `Codex`, `Co-Authored-By`, `Generated by`, or similar signatures.
- Before committing a rename or moved file — or a changed `rule_id` / predefined list name / other identifier referenced by name — grep the old name across `docs/`, `AGENTS.md`, `.claude/rules/**`, and the Go sources, and update every reference in the same commit. Markdown link targets and rule cross-references are not caught by `make rules-validate` / `make test`.

## Large changes

For large feature additions or substantial behavior changes, write a Markdown Design Doc before implementation.
Use `.claude/rules/50-design-docs.md` for the recommended format.
Use it mainly as a local working document to keep the direction stable and track progress.
If communication needs it, copy or summarize the relevant parts into GitHub Issues.
