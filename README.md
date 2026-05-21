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

CI/CD jobs build, release, and deploy software — and increasingly manage production infrastructure through IaC. They run with cloud credentials, signing keys, and registry tokens, which makes the CI/CD Pipeline itself the prize. Recent supply chain incidents have shown that the attack path now runs *through* trusted developer tools — CI/CD Pipelines, package dependencies, container images — and the malicious behavior happens **inside the job**: processes execute, files are read, connections are made, and the CI/CD Pipeline disappears before anyone sees it.

Open source runtime detection exists everywhere else — Falco for Kubernetes, Tracee and Tetragon for cloud workloads, Wazuh and OSQuery for endpoints. CI/CD runtime has nothing equivalent. Sigstore proves *where* an artifact was built, but not *what ran* during the build, what it touched, or where it connected — and that is exactly the evidence teams need to detect attacks and respond.

**cicd-sensor closes that gap.** eBPF inside the CI/CD Pipeline captures process, network, and file activity while the job is still alive, so the evidence outlives the CI/CD Pipeline — for real-time detection, incident response, and verifiable build records.

- For **Developers and SRE**, it detects suspicious activity during builds and releases and keeps runtime records and attestations that others can verify later.
- For **Enterprise security teams**, it provides Job Result Logs, Detection Logs, and Runtime Telemetry Logs that support monitoring, incident response, and forensics.

## Quick start

On GitHub-hosted runners, add the cicd-sensor action as the first step in your workflow.

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: cicd-sensor/cicd-sensor-action@v0.0.2
      - uses: actions/checkout@v6

      - name: Build
        run: make test
```

## Demo

<p align="center">
  <img src="docs/assets/demo.gif" alt="cicd-sensor GitHub Actions demo" width="100%">
</p>

## Key features

- **eBPF-powered observability** — observes process execution, network connections, and file access at the kernel level.
- **CEL-based rule engine** — monitors CI/CD runtime events with YAML rules and CEL conditions.
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
