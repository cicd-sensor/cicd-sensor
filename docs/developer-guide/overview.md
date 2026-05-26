# Developer Guide Overview

The Developer Guide is for people who read, modify, or contribute to the cicd-sensor implementation.

For Phase0, the goal is not to document every internal package.
The goal is to understand the main subsystem responsibilities and boundaries.

## Repository layout

| Path | Role |
| --- | --- |
| `cmd/cicd-sensor` | CLI for the Agent and CI integration |
| `cmd/cicd-sensor-manager` | Manager server |
| `cmd/cicd-sensorctl` | Utility CLI for reports, attestations, rule validation, and related tasks |
| `internal/agent` | Agent runtime that observes CI/CD job runtime |
| `internal/rule` | RuleSet / RuleModifier schema, merge, CEL compile, and evaluation |
| `internal/manager` | Config service, collector ingest, and output routing |
| `internal/ctl` | Report and attestation generation |

## Reading order

Read the Agent runtime pages first:

1. [Agent Architecture](agent.md): job lifecycle, provider flow, and runtime entrypoints.
2. [Agent Ownership Boundaries](agent-ownership-boundaries.md): where Agent, JobRegistry, Job, and JobScopeState own state.
3. [eBPF Runtime](ebpf-runtime.md): cgroup tracking, kernel hooks, and the KernelTracker boundary.
4. [Rule Engine](rule-engine.md): how runtime events are evaluated against compiled rules.

Then read the Manager control-plane page separately:

5. [Manager Architecture](manager.md): config, rules, and log delivery outside the Agent runtime path.
