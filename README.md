<!-- markdownlint-disable MD041 -->
> 🚧 **Pre-release: Active development.**
> cicd-sensor is currently in pre-release and under active development. Feedback is very welcome.

<p align="center">
  <img src="cicd-sensor.png" alt="cicd-sensor logo" width="160">
</p>
<h1 align="center">cicd-sensor</h1>
<p align="center"><strong>Think EDR, but for CI/CD Pipelines.</strong><br>Open-source eBPF-powered runtime security sensor for GitHub Actions and GitLab CI/CD.<br>→ <a href="https://cicd-sensor.github.io/">Full documentation</a></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Language-Go-00ADD8?logo=go" alt="Language">
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux" alt="Platform">
  <img src="https://img.shields.io/badge/Open%20Source-Yes-brightgreen" alt="Open Source">
</p>

<hr>

## Demo

<div align="center">
  <table>
    <tr><td>
      <img src="docs/assets/demo.gif" alt="cicd-sensor GitHub Actions demo" width="560">
    </td></tr>
  </table>
  <sub>Example: cicd-sensor added to a GitHub Actions workflow. The resulting reports are viewable in the GitHub job summary.</sub>
</div>

## What cicd-sensor does

When a compromised dependency in a CI/CD job steals your cloud credentials and leaks them, would you catch it? Would you have the logs to investigate afterward? cicd-sensor is an open-source sensor that lets every team answer both.

**Detection:** Detects supply-chain attacks at runtime using process ancestry (e.g. credential access from a process descended from `npm install`) and correlation across signals (e.g. multiple credential categories read in one job). Baseline rules target patterns seen in real CI/CD attacks, and are opt-out: turn them off if you only want the logs and evidence below.

**Logs and evidence:** Per run, cicd-sensor can emit logs for review, alerting, and forensics, routed through cicd-sensor Manager to cloud sinks like S3, GCS, and Pub/Sub. The cicd-sensor-action can also produce a graphical report and a build attestation per run. Your data stays under your control. cicd-sensor never sends anything to servers operated by the cicd-sensor project.

## Quick start

On GitHub-hosted runners, add the cicd-sensor action as the first step in your workflow.

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: cicd-sensor/cicd-sensor-action@3a3a447ad3668a3e205bf1273f2f2806bbbd30f3 # v0.0.33
```

For self-hosted GitHub Actions or GitLab CI/CD, see the [User Guide](https://cicd-sensor.github.io/user-guide/overview.html).

## Why CI/CD runtime needs this

CI/CD pipelines build, release, deploy, and manage cloud infrastructure, and they hold the cloud credentials, signing keys, and registry tokens to do it. Supply-chain attackers run inside those jobs and disappear with the evidence when the job ends.

Most other runtimes have their open-source defenders: Falco, Tetragon, Tracee, Wazuh, OSQuery. Open-source coverage for CI/CD runtime has lagged behind. Sigstore proved *where* and *how* artifacts were built; cicd-sensor preserves *what actually ran* so teams can detect, respond, and audit.

## Feature comparison

| Capability | cicd-sensor | Harden-Runner (Free) | Comment |
| --- | --- | --- | --- |
| **Licensing & deployment** | | | |
| Open source | ✅ Yes | ✅ Yes | |
| Data privacy | ✅ Self-hosted | SaaS backend | cicd-sensor runs entirely in your infrastructure, so logs and events stay in your environment. |
| **Platform coverage** | | | |
| Private repos | ✅ Yes | ❌ No | |
| Self-hosted runners | ✅ Yes | ❌ No | Enforcing self-hosted runners enables organization-wide log collection across every job. |
| GitHub Actions support | ✅ Yes | ✅ Yes | |
| GitLab CI/CD support | ✅ Yes | ❌ No | |
| **Capabilities** | | | |
| Detection rules | ✅ Yes | ✅ Yes | |
| Flexible custom rules | ✅ Yes | 🔶 Limited | cicd-sensor rules cover process ancestry, file access, and correlation across signals; Harden-Runner is mainly a network egress allowlist. |
| Network blocking | 🔶 Partial | ✅ Yes | cicd-sensor kills the process and stops the job on detection instead of filtering traffic like a firewall. |
| Log export | ✅ Yes | ❌ No | |

<sub>This table compares the free version of Harden-Runner. StepSecurity's paid platform adds more, such as private repository and self-hosted runner support, dashboards, and policy management.</sub>

<sub>Based on public information as of May 2026. Corrections welcome.</sub>

## Supported CI/CD pipelines

| Platform | Environment | Status |
| --- | --- | --- |
| GitHub Actions | GitHub-hosted runner | ✅ Supported |
| GitHub Actions | Self-hosted runner on a machine | ✅ Supported |
| GitHub Actions | Actions Runner Controller on Kubernetes | 🧪 Preview support |
| GitLab CI/CD | GitLab Runner Docker executor | ✅ Supported |
| GitLab CI/CD | GitLab Runner Kubernetes executor | 🧪 Preview support |
| GitLab CI/CD | GitLab-hosted runner | ❌ Not supported (technical constraints) |

Works on both public and private repositories, with no third-party SaaS dependency.

Linux kernel: 5.15 or later on `amd64`, 6.1 or later on `arm64`.

## Rules

cicd-sensor ships with a set of baseline rules. See the [Baseline Rules guide](https://cicd-sensor.github.io/user-guide/baseline-rules.html) for how they work; the rule definitions themselves live in [`rules/`](rules/). You can also write your own rules, or turn the baseline off entirely.

## Documentation

- [Getting Started](https://cicd-sensor.github.io/): what cicd-sensor is and how to start.
- [User Guide](https://cicd-sensor.github.io/user-guide/overview.html): deployment paths for GitHub Actions and GitLab CI/CD.
- [Rules](https://cicd-sensor.github.io/user-guide/rules.html): write detection, collection, and correlation rules.
- [Logging](https://cicd-sensor.github.io/user-guide/logging.html): log format delivered by the manager.
- [Attestation predicate](https://cicd-sensor.github.io/user-guide/attestation-predicate.html): runtime-trace predicate for CI/CD runtime evidence.
- [Developer Guide](https://cicd-sensor.github.io/developer-guide/overview.html): agent, eBPF runtime, manager, and rule engine internals.

## About the project

> [!NOTE]
> **About the creator:** cicd-sensor is a vendor-neutral open-source project, created and maintained by [Hiroki Suezawa (@rung)](https://www.suezawa.net), author of the [Common Threat Matrix for CI/CD Pipeline](https://github.com/rung/threat-matrix-cicd), contributor to the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/), and early contributor to [OSC&R / pbom.dev](https://pbom.dev/). cicd-sensor was started as an individual project to stay close to the open-source community that is on the receiving end of supply-chain attacks.

A read-only official mirror is published at [gitlab.com/cicd-sensor/cicd-sensor](https://gitlab.com/cicd-sensor/cicd-sensor). GitHub is the canonical source; the GitLab mirror is synced periodically.

## License

Apache License 2.0 ([LICENSE](LICENSE)). BPF source under `internal/agent/bpf/` is dual-licensed `GPL-2.0-only OR BSD-2-Clause` ([details](internal/agent/bpf/README.md#licensing)).
