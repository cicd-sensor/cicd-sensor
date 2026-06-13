<div align="center">
  <img src="assets/cicd-sensor.png" alt="cicd-sensor logo" width="160">
  <h1><a href="https://github.com/cicd-sensor/cicd-sensor">cicd-sensor</a></h1>
</div>

<p align="center"><strong>Think EDR, but for CI/CD Pipelines.</strong><br>Open-source eBPF-powered runtime security sensor for GitHub Actions and GitLab CI/CD.</p>

<style>
  .coal .prerelease-callout,
  .navy .prerelease-callout,
  .ayu .prerelease-callout {
    background: #2d2419 !important;
    color: #e8dcc4 !important;
    border-left-color: #d97706 !important;
  }
</style>
<div class="prerelease-callout" style="border-left: 4px solid #f59e0b; background: #fffbeb; padding: 0.6rem 1rem; margin: 0.5rem 0;">
  <strong>Pre-release: Active development</strong><br>
  cicd-sensor is currently in pre-release and under active development. Feedback is very welcome.
</div>

## Demo

<div style="text-align: center; margin: 0.5rem 0;">
  <img src="assets/demo.gif" alt="cicd-sensor GitHub Actions demo" width="560" style="border: 1px solid #d0d7de; border-radius: 8px;">
  <div style="margin-top: 0.4rem;"><sub>Example: cicd-sensor added to a GitHub Actions workflow. The resulting reports are viewable in the GitHub job summary.</sub></div>
</div>

## What cicd-sensor does

**Detection:** Detects supply-chain attacks at runtime using process ancestry (e.g. credential access from a process descended from `npm install`) and correlation across signals (e.g. multiple credential categories read in one job). Baseline rules target patterns seen in real CI/CD attacks.

**Logs and evidence:** Per run, cicd-sensor can emit logs for review, alerting, and forensics, routed through cicd-sensor Manager to cloud sinks like S3, GCS, and Pub/Sub. The cicd-sensor-action can also produce a graphical report and a build attestation per run. Your data stays under your control. cicd-sensor never sends anything to servers operated by the cicd-sensor project.

## Getting Started

On GitHub-hosted runners, add the cicd-sensor action as the first step in your workflow.

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: cicd-sensor/cicd-sensor-action@3a3a447ad3668a3e205bf1273f2f2806bbbd30f3 # v0.0.33
```

See [GitHub-hosted runner](user-guide/github-hosted.md) for details.
For machine runners, ARC runner scale sets, or GitLab Runner executors, choose a deployment path from the [User Guide](user-guide/overview.md).

## Why CI/CD runtime needs this

CI/CD pipelines build, release, deploy, and manage cloud infrastructure, and they hold the cloud credentials, signing keys, and registry tokens to do it. Supply-chain attackers run inside those jobs and disappear with the evidence when the job ends.

Most other runtimes have their open-source defenders: Falco, Tetragon, Tracee, Wazuh, OSQuery. Open-source coverage for CI/CD runtime has lagged behind. Sigstore proved *where* and *how* artifacts were built; cicd-sensor preserves *what actually ran* so teams can detect, respond, and audit.

## Supported CI/CD Pipelines

cicd-sensor treats GitHub Actions and GitLab CI/CD as supported targets.
It works on both public and private repositories, with no third-party SaaS dependency.
For platform and runner environment status, see [Platform support](user-guide/overview.md#platform-support).

## About the project

<style>
  .coal .creator-callout,
  .navy .creator-callout,
  .ayu .creator-callout {
    background: #1a3a32 !important;
    color: #d8efe6 !important;
    border-left-color: #2dd4bf !important;
  }
</style>
<div class="creator-callout" style="border-left: 4px solid #0f766e; background: #ecfdf5; padding: 0.6rem 1rem; margin: 0.5rem 0;">
  <strong>About the creator</strong><br>
  cicd-sensor is an independent open-source project created and maintained by <a href="https://www.suezawa.net">Hiroki Suezawa (@rung)</a>, author of the <a href="https://github.com/rung/threat-matrix-cicd">Common Threat Matrix for CI/CD Pipeline</a>, contributor to the <a href="https://owasp.org/www-project-top-10-ci-cd-security-risks/">OWASP Top 10 CI/CD Security Risks</a>, and early contributor to <a href="https://pbom.dev/">OSC&amp;R / pbom.dev</a>. cicd-sensor is the runtime defender that work has been pointing to.
</div>
