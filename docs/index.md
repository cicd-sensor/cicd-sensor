<div align="center">
  <img src="assets/cicd-sensor.png" alt="cicd-sensor logo" width="160">
  <h1><a href="https://github.com/cicd-sensor/cicd-sensor">cicd-sensor</a></h1>
</div>

<p align="center"><strong>Open-source eBPF-powered CI/CD runtime security sensor</strong></p>

<div style="border-left: 4px solid #f59e0b; background: #fffbeb; padding: 0.9rem 1rem; margin: 1rem 0;">
  <strong>Beta Version</strong><br>
  cicd-sensor is currently in beta. Feedback, real-world testing, rule development, and validation in CI/CD environments are very welcome.
</div>

[cicd-sensor](https://github.com/cicd-sensor/cicd-sensor) is an open-source eBPF-powered CI/CD runtime security sensor for GitHub Actions and GitLab CI/CD.
It observes CI/CD runtime behavior, detects attacks and suspicious activity during builds and releases, and leaves evidence that security teams can use for incident response and build verification.

CI/CD is no longer only a test runner. It is used to build, release, publish, and deploy software, and those jobs often hold powerful long-lived and short-lived credentials: cloud credentials, package registry tokens, release signing keys, and deployment secrets.
cicd-sensor is a tool for defending that runtime.
For Developers and SREs, it provides a way to detect suspicious activity during builds and releases and to keep runtime records and attestations that others can verify later.
For Enterprise security teams, it provides Job Result Logs, Detection Logs, and Runtime Telemetry Logs that support monitoring, incident response, and forensics.

## Getting Started

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

See [GitHub-hosted runner](user-guide/github-hosted.md) for details.
For self-hosted runner fleets or GitLab CI/CD, choose a deployment path from the [User Guide](user-guide/overview.md).

<div style="position: relative; margin: 1.25rem 0;">
  <div style="position: absolute; top: 1rem; right: 1rem; padding: 0.35rem 0.85rem; border: 2px solid #0f766e; border-radius: 4px; background: #ecfdf5; color: #134e4a; font-size: 2.4rem; font-weight: 700; line-height: 1.1;">Demo</div>
  <img src="assets/demo.gif" alt="cicd-sensor GitHub Actions demo" width="100%" style="border: 1px solid #d0d7de; border-radius: 8px;">
</div>

## Motivation

CI/CD is the runtime where software is built, released, deployed, and where Infrastructure as Code often manages production infrastructure.
That makes CI/CD jobs high-value execution environments with powerful credentials available at runtime.

Recent supply chain incidents changed the urgency of this problem.
They showed that trusted developer tools, security scanners, GitHub Actions, package dependencies, and IDE extensions can become the execution path for credential theft inside developer and CI/CD environments.
When a trusted tool is weaponized, the malicious behavior happens inside the job: processes execute, files are read, network connections are made, and credentials may be harvested before the runner disappears.

cicd-sensor is developed by [Hiroki Suezawa (rung)](https://www.suezawa.net).
I have worked on CI/CD attacks and software supply chain security for more than five years.
Through [Common Threat Matrix for CI/CD Pipeline](https://github.com/rung/threat-matrix-cicd), review work on the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/), and early involvement in [OSC&R / pbom.dev](https://pbom.dev/), I have helped organize threat models and defensive requirements in this area.

That work kept pointing to the same gap: CI/CD risks are better understood than before, but CI/CD runtime still lacks practical ways to detect attacks in real time and preserve the logs needed for response.
Kubernetes has runtime security tools such as Falco, endpoints have EDR, and cloud workloads have mature detection and telemetry options.
CI/CD jobs, however, are short-lived, and the evidence disappears quickly unless something records it while the job is running.

Projects such as Sigstore have made major progress in proving where an artifact was built.
But if malicious behavior happened during the build runtime, teams still need evidence of what actually ran, what it touched, and where it connected.
That evidence is still hard to get from CI/CD systems today.

cicd-sensor exists to close that gap: to make CI/CD runtime visible, detect attacks while they happen, and preserve the evidence needed for investigation.

> Disclaimer: cicd-sensor is a personal open-source project. The views expressed here are my own and do not represent my employer.

## Who It Helps

| Audience | What cicd-sensor provides |
| --- | --- |
| Developers and SRE | A way to detect suspicious activity during builds and releases. Runtime records, connection information, and attestations can be reviewed later and used as verifiable build evidence. |
| Enterprise security team | Three log streams for CI/CD Runtime Security: Job Result Log, Detection Log, and Runtime Telemetry Log. These give security teams a path from monitoring to incident response and forensics. |

## Key Features

- **eBPF-powered observability**: observes process execution, network connections, and file access at the kernel level.
- **CEL-based rule engine**: monitors CI/CD runtime events with YAML rules and CEL conditions.
- **Correlation detection**: detects combinations of events, such as credential access plus suspicious execution, instead of relying only on single events.
- **Graphical report**: generates a report that lets you review job runtime activity after the build.
- **Runtime-trace attestation predicate**: generates an in-toto compatible runtime-trace predicate to improve build explainability and verifiability.
- **Centralized management**: cicd-sensor Manager distributes policy, config, and output routing across runner fleets.

## Supported CI/CD Pipelines

cicd-sensor treats GitHub Actions and GitLab CI/CD as supported targets.
For platform and runner environment status, see [Platform support](user-guide/overview.md#platform-support).

## Next Steps

- [User Guide](user-guide/overview.md): deploy cicd-sensor into CI/CD pipelines.
- [Rules](user-guide/rules.md): write detection rules.
- [Developer Guide](developer-guide/overview.md): understand the cicd-sensor implementation.
