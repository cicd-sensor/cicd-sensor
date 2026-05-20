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

1. [Agent Architecture](agent.md): how CI/CD job lifecycle connects to eBPF runtime events.
2. [eBPF Runtime](ebpf-runtime.md): cgroup tracking, kernel hooks, and the KernelTracker boundary.
3. [Manager Architecture](manager.md): the control plane for config, rules, and log delivery.
4. [Rule Engine](rule-engine.md): how the User Guide rule authoring surface maps to the implementation.
