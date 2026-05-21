<!-- markdownlint-disable MD041 -->
> 🚧 **Currently under development. Not yet ready for use.**
> cicd-sensor is in beta. Feedback, real-world testing, rule development, and validation in CI/CD environments are very welcome.

<p align="center">
  <img src="cicd-sensor.png" alt="cicd-sensor logo" width="160">
</p>
<h1 align="center">cicd-sensor</h1>
<p align="center"><strong>Open-source eBPF-powered CI/CD runtime security sensor</strong><br>for GitHub Actions and GitLab CI/CD.<br>→ <a href="https://cicd-sensor.github.io/">Full documentation</a></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Language-Go-00ADD8?logo=go" alt="Language">
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux" alt="Platform">
  <img src="https://img.shields.io/badge/Open%20Source-Yes-brightgreen" alt="Open Source">
</p>

<hr>

CI/CD Pipelines build, release, and deploy software — and they hold the keys to do it: cloud credentials, signing keys, registry tokens. That makes them the prize.

Entering 2026, supply chain incidents are accelerating. Attackers slip *through* trusted CI/CD Pipelines, package dependencies, and container images, run **inside the job**, and disappear with the evidence when the CI/CD Pipeline ends.

Every other runtime has its open-source defender — Falco, Tetragon, Tracee, Wazuh, OSQuery. CI/CD runtime has nothing. Sigstore brought us cryptographic proof of *where* and *how* an artifact was built; the next piece — *what actually ran* during the build, what it touched, where it connected — is the runtime evidence defenders still need to detect attacks and respond.

**That is the gap. cicd-sensor is built to close it** — using eBPF inside the CI/CD Pipeline to make runtime visible, detect attacks while they happen, and preserve the evidence teams need to respond.

- **Developers — OSS or commercial — should be able to see what their own pipelines actually do, and prove it later** — process, network, and file activity across build, release, and deploy, plus a verifiable attestation predicate.
- **Security teams — defending against supply chain attacks — need tools built for the runtime** — real-time detection plus the runtime logs they actually need, like Job Result, Detection, and Runtime Telemetry, giving CI/CD the detection, incident response, and forensics environment it has been missing.

> [!NOTE]
> **About the author** — Built by [Hiroki Suezawa (@rung)](https://www.suezawa.net), author of the [Common Threat Matrix for CI/CD Pipeline](https://github.com/rung/threat-matrix-cicd), contributor to the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/), and early contributor to [OSC&R / pbom.dev](https://pbom.dev/). cicd-sensor is the runtime defender that work has been pointing to.

## Quick start

On GitHub-hosted runners, add the cicd-sensor action as the first step in your workflow.

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: cicd-sensor/cicd-sensor-action@198d4f8e7b83b54ee6af1d4e7dcc5be00a675de7 # v0.0.9
```

## Demo

<div align="center">
  <table>
    <tr><td>
      <img src="docs/assets/demo.gif" alt="cicd-sensor GitHub Actions demo" width="720">
    </td></tr>
  </table>
</div>

## Key features

- **eBPF-powered observability** — observes process execution, network connections, and file access at the kernel level.
- **CEL-based rule engine** — monitors CI/CD runtime events with readable, flexible expressions.
- **Correlation detection** — detects combinations of events such as credential access plus suspicious execution, instead of relying only on single events.
- **Runtime security logs** — emits Job Result Logs, Detection Logs, and Runtime Telemetry Logs for real-time detection, triage, incident response, and forensics.
- **Runtime report and attestation** — generates a graphical report and an in-toto compatible runtime-trace attestation predicate so teams can review and verify CI/CD runtime activity.
- **Centralized management** — cicd-sensor Manager distributes policy, config, and output routing across runner fleets.

## Supported CI/CD pipelines

| Platform | Environment | Status |
| --- | --- | --- |
| GitHub Actions | GitHub-hosted runner | Supported |
| GitHub Actions | Self-hosted Machine Runner | Supported |
| GitHub Actions | Actions Runner Controller on Kubernetes | Planned |
| GitLab CI/CD | Self-hosted Container Executor | Supported |
| GitLab CI/CD | Self-hosted Kubernetes Executor | Planned |
| GitLab CI/CD | GitLab-hosted runner | Not supported (technical constraints) |

Linux kernel: 5.15 or later on `x86_64`, 6.1 or later on `aarch64`.

## Documentation

- [Getting Started](https://cicd-sensor.github.io/) — what cicd-sensor is and how to start.
- [User Guide](https://cicd-sensor.github.io/user-guide/overview.html) — deployment paths for GitHub Actions and GitLab CI/CD.
- [Rules](https://cicd-sensor.github.io/user-guide/rules.html) — write detection, collection, and correlation rules.
- [Logging](https://cicd-sensor.github.io/user-guide/logging.html) — log format delivered by the manager.
- [Developer Guide](https://cicd-sensor.github.io/developer-guide/overview.html) — agent, eBPF runtime, manager, and rule engine internals.

## License

Apache License 2.0 ([LICENSE](LICENSE)). BPF source under `internal/agent/bpf/` is dual-licensed `GPL-2.0-only OR BSD-2-Clause` ([details](internal/agent/bpf/README.md#licensing)).
