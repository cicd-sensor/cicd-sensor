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
- **Security teams — defending against supply chain attacks — need tools built for the runtime** — real-time detection plus the runtime logs they actually need, like Summary, Detection, and Runtime Event Logs, delivered through cloud services like S3 into the SIEM teams already run, giving CI/CD the detection, incident response, and forensics environment it has been missing.

> [!NOTE]
> **About the creator** — cicd-sensor is a vendor-neutral open-source project, created and maintained by [Hiroki Suezawa (@rung)](https://www.suezawa.net) — author of the [Common Threat Matrix for CI/CD Pipeline](https://github.com/rung/threat-matrix-cicd), contributor to the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/), and early contributor to [OSC&R / pbom.dev](https://pbom.dev/). cicd-sensor was started as an individual project to stay close to the open-source community that is on the receiving end of supply-chain attacks.

## Quick start

On GitHub-hosted runners, add the cicd-sensor action as the first step in your workflow.

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: cicd-sensor/cicd-sensor-action@6ee257338e68af2b279b321b3346fe5f385aa498 # v0.0.29
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

- **eBPF-powered observability** — kernel-level visibility into process, network, and file activity.
- **Continuously updated detection baseline** — baseline rules stay current; layer your own org or project rules on top.
- **Correlation detection** — combine multiple signals (e.g. credential read + suspicious exec) into a single detection, not just single events.
- **Runtime security logs** — Summary, Detection, and Runtime Event Logs delivered to cloud services like S3 and into your SIEM for triage, incident response, and forensics.
- **Runtime report and attestation** — per-job graphical report plus an in-toto runtime-trace attestation predicate for verifiable review.
- **Centralized management** — cicd-sensor Manager distributes rules, config, and log routing across runner fleets.
- **User-controlled runtime data** — runtime data stays in your infrastructure; nothing is sent to servers operated by the cicd-sensor project.

## Supported CI/CD pipelines

| Platform | Environment | Status |
| --- | --- | --- |
| GitHub Actions | GitHub-hosted runner | Supported |
| GitHub Actions | Self-hosted Machine Runner | Supported |
| GitHub Actions | Actions Runner Controller on Kubernetes | Planned |
| GitLab CI/CD | Self-hosted Docker executor | Supported |
| GitLab CI/CD | Self-hosted Kubernetes executor | Planned |
| GitLab CI/CD | GitLab-hosted runner | Not supported (technical constraints) |

Linux kernel: 5.15 or later on `amd64`, 6.1 or later on `arm64`.

## Documentation

- [Getting Started](https://cicd-sensor.github.io/) — what cicd-sensor is and how to start.
- [User Guide](https://cicd-sensor.github.io/user-guide/overview.html) — deployment paths for GitHub Actions and GitLab CI/CD.
- [Rules](https://cicd-sensor.github.io/user-guide/rules.html) — write detection, collection, and correlation rules.
- [Logging](https://cicd-sensor.github.io/user-guide/logging.html) — log format delivered by the manager.
- [Attestation predicate](https://cicd-sensor.github.io/user-guide/attestation-predicate.html) — runtime-trace predicate for CI/CD runtime evidence.
- [Developer Guide](https://cicd-sensor.github.io/developer-guide/overview.html) — agent, eBPF runtime, manager, and rule engine internals.

## Mirror

A read-only official mirror of this repository is published at [gitlab.com/cicd-sensor/cicd-sensor](https://gitlab.com/cicd-sensor/cicd-sensor). GitHub is the canonical source; the GitLab mirror is synced periodically from this repository.

## License

Apache License 2.0 ([LICENSE](LICENSE)). BPF source under `internal/agent/bpf/` is dual-licensed `GPL-2.0-only OR BSD-2-Clause` ([details](internal/agent/bpf/README.md#licensing)).
