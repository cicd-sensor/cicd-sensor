<!-- markdownlint-disable MD041 -->
> 🚧 **Pre-release: Active development.**
> cicd-sensor is currently in pre-release and under active development. Feedback is very welcome.

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

CI/CD Pipelines build, release, deploy software, and manage cloud infrastructure — and they hold the keys to do it: cloud credentials, signing keys, registry tokens. That makes them the prize.

Entering 2026, supply chain incidents are accelerating. Attackers slip *through* trusted CI/CD Pipelines, package dependencies, and container images, run **inside the job**, and disappear with the evidence when the CI/CD Pipeline ends.

Every other runtime has its open-source defender — Falco, Tetragon, Tracee, Wazuh, OSQuery. CI/CD runtime has nothing. Sigstore brought us cryptographic proof of *where* and *how* an artifact was built; the next piece — *what actually ran* during the job, what it touched, where it connected — is the runtime evidence defenders still need to detect attacks and respond.

**That is the gap. cicd-sensor is built to close it** — using eBPF inside the CI/CD Pipeline to make runtime visible, detect attacks while they happen, and preserve the evidence teams need to respond.

- **Developers — OSS or commercial — should be able to see what their own pipelines actually do, and prove it later** — observing process, network, and file activity across build, release, deploy, and cloud infrastructure management, and proving it with a verifiable attestation predicate.
- **Security teams — defending against supply chain attacks — need tools built for the runtime** — real-time detection plus the runtime logs they actually need, like Summary, Detection, and Runtime Event Logs, giving CI/CD the detection, incident response, and forensics environment it has been missing.

> [!NOTE]
> **About the creator** — cicd-sensor is an independent open-source project created and maintained by [Hiroki Suezawa (@rung)](https://www.suezawa.net), author of the [Common Threat Matrix for CI/CD Pipeline](https://github.com/rung/threat-matrix-cicd), contributor to the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/), and early contributor to [OSC&R / pbom.dev](https://pbom.dev/). cicd-sensor is the runtime defender that work has been pointing to.

## Quick start

On GitHub-hosted runners, add the cicd-sensor action as the first step in your workflow.

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: cicd-sensor/cicd-sensor-action@ea0992fdf1131f1b19265fc5b324c21245dde397 # v0.0.22
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
- **Continuously updated detection baseline** — fetches baseline rules for CI/CD runtime detection, with local and managed rule layers for organization-specific needs.
- **Correlation detection** — lets baseline and custom rules combine signals such as credential access plus suspicious execution, instead of relying only on single events.
- **Runtime security logs** — emits Summary Logs, Detection Logs, and Runtime Event Logs for real-time detection, triage, incident response, and forensics.
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

Linux kernel: 5.15 or later on `amd64`, 6.1 or later on `arm64`.

## Documentation

- [Getting Started](https://cicd-sensor.github.io/) — what cicd-sensor is and how to start.
- [User Guide](https://cicd-sensor.github.io/user-guide/overview.html) — deployment paths for GitHub Actions and GitLab CI/CD.
- [Rules](https://cicd-sensor.github.io/user-guide/rules.html) — write detection, collection, and correlation rules.
- [Logging](https://cicd-sensor.github.io/user-guide/logging.html) — log format delivered by the manager.
- [Attestation predicate](https://cicd-sensor.github.io/user-guide/attestation-predicate.html) — runtime-trace predicate for CI/CD runtime evidence.
- [Developer Guide](https://cicd-sensor.github.io/developer-guide/overview.html) — agent, eBPF runtime, manager, and rule engine internals.

## License

Apache License 2.0 ([LICENSE](LICENSE)). BPF source under `internal/agent/bpf/` is dual-licensed `GPL-2.0-only OR BSD-2-Clause` ([details](internal/agent/bpf/README.md#licensing)).
