<div align="center">
  <img src="assets/cicd-sensor.png" alt="cicd-sensor logo" width="160">
  <h1><a href="https://github.com/cicd-sensor/cicd-sensor">cicd-sensor</a></h1>
</div>

<p align="center"><strong>Open-source eBPF-powered CI/CD runtime security sensor</strong></p>

<style>
  .coal .prerelease-callout,
  .navy .prerelease-callout,
  .ayu .prerelease-callout {
    background: #2d2419 !important;
    color: #e8dcc4 !important;
    border-left-color: #d97706 !important;
  }
</style>
<div class="prerelease-callout" style="border-left: 4px solid #f59e0b; background: #fffbeb; padding: 0.9rem 1rem; margin: 1rem 0;">
  <strong>Pre-release: Active development</strong><br>
  cicd-sensor is currently in pre-release and under active development. Feedback is very welcome.
</div>

CI/CD Pipelines build, release, deploy software, and manage cloud infrastructure — and they hold the keys to do it: cloud credentials, signing keys, registry tokens.
That makes them the prize.

Entering 2026, supply chain incidents are accelerating.
Attackers slip *through* trusted CI/CD Pipelines, package dependencies, and container images, run **inside the job**, and disappear with the evidence when the CI/CD Pipeline ends.

Every other runtime has its open-source defender — Falco, Tetragon, Tracee, Wazuh, OSQuery.
CI/CD runtime has nothing.
Sigstore brought us cryptographic proof of *where* and *how* an artifact was built; the next piece — *what actually ran* during the job, what it touched, where it connected — is the runtime evidence defenders still need to detect attacks and respond.

**That is the gap. [cicd-sensor](https://github.com/cicd-sensor/cicd-sensor) is built to close it** — using eBPF inside the CI/CD Pipeline to make runtime visible, detect attacks while they happen, and preserve the evidence teams need to respond.

- **Developers — OSS or commercial — should be able to see what their own pipelines actually do, and prove it later** — observing process, network, and file activity across build, release, deploy, and cloud infrastructure management, and proving it with a verifiable attestation predicate.
- **Security teams — defending against supply chain attacks — need tools built for the runtime** — real-time detection plus the runtime logs they actually need, like Summary, Detection, and Runtime Event Logs, giving CI/CD the detection, incident response, and forensics environment it has been missing.

<style>
  .coal .creator-callout,
  .navy .creator-callout,
  .ayu .creator-callout {
    background: #1a3a32 !important;
    color: #d8efe6 !important;
    border-left-color: #2dd4bf !important;
  }
</style>
<div class="creator-callout" style="border-left: 4px solid #0f766e; background: #ecfdf5; padding: 0.9rem 1rem; margin: 1.5rem 0;">
  <strong>About the creator</strong><br>
  cicd-sensor is an independent open-source project created and maintained by <a href="https://www.suezawa.net">Hiroki Suezawa (@rung)</a>, author of the <a href="https://github.com/rung/threat-matrix-cicd">Common Threat Matrix for CI/CD Pipeline</a>, contributor to the <a href="https://owasp.org/www-project-top-10-ci-cd-security-risks/">OWASP Top 10 CI/CD Security Risks</a>, and early contributor to <a href="https://pbom.dev/">OSC&amp;R / pbom.dev</a>. cicd-sensor is the runtime defender that work has been pointing to.
</div>

## Getting Started

On GitHub-hosted runners, add the cicd-sensor action as the first step in your workflow.

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: cicd-sensor/cicd-sensor-action@ea0992fdf1131f1b19265fc5b324c21245dde397 # v0.0.22
```

See [GitHub-hosted runner](user-guide/github-hosted.md) for details.
For self-hosted runner fleets or GitLab CI/CD, choose a deployment path from the [User Guide](user-guide/overview.md).

<div style="position: relative; margin: 1.25rem 0;">
  <div style="position: absolute; top: 1rem; right: 1rem; padding: 0.35rem 0.85rem; border: 2px solid #0f766e; border-radius: 4px; background: #ecfdf5; color: #134e4a; font-size: 2.4rem; font-weight: 700; line-height: 1.1;">Demo</div>
  <img src="assets/demo.gif" alt="cicd-sensor GitHub Actions demo" width="100%" style="border: 1px solid #d0d7de; border-radius: 8px;">
</div>

## Key Features

- **eBPF-powered observability**: observes process execution, network connections, and file access at the kernel level.
- **Continuously updated detection baseline**: fetches baseline rules for CI/CD runtime detection, with local and managed rule layers for organization-specific needs.
- **Correlation detection**: lets baseline and custom rules combine signals, such as credential access plus suspicious execution, instead of relying only on single events.
- **Runtime security logs**: provides Summary Logs, Detection Logs, and Runtime Event Logs for real-time detection, triage, incident response, and forensics.
- **Runtime report and attestation**: generates a graphical report and an in-toto compatible runtime-trace attestation predicate so teams can review and verify CI/CD runtime activity.
- **Centralized management**: cicd-sensor Manager distributes policy, config, and output routing across runner fleets.

## Supported CI/CD Pipelines

cicd-sensor treats GitHub Actions and GitLab CI/CD as supported targets.
For platform and runner environment status, see [Platform support](user-guide/overview.md#platform-support).
