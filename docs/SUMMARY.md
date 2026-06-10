# Summary

- [Getting Started](index.md)

# User Guide

- [Overview](user-guide/overview.md)
- [GitHub-hosted runner](user-guide/github-hosted.md)
- [Machine runner install](user-guide/self-hosted-install.md)
  - [GitHub Actions machine runner](user-guide/github-self-hosted.md)
  - [GitLab Runner Docker executor](user-guide/gitlab-ci.md)
- [Kubernetes runner install](user-guide/kubernetes/index.md)
  - [GitHub ARC runner scale sets](user-guide/kubernetes/github-arc.md)
  - [GitLab Runner Kubernetes executor](user-guide/kubernetes/gitlab-runner.md)
- [Manager](user-guide/manager.md)
- [Rules](user-guide/rules.md)
  - [Baseline Rules](user-guide/baseline-rules.md)
  - [RuleSet](user-guide/rule-set.md)
  - [Event types](user-guide/rule-event-types.md)
  - [CEL conditions](user-guide/rule-cel-conditions.md)
  - [Correlation](user-guide/rule-correlation.md)
  - [Rule modifiers](user-guide/rule-modifiers.md)
  - [Rule development](user-guide/rule-development.md)
- [Logging](user-guide/logging.md)
- [Attestation predicate](user-guide/attestation-predicate.md)

# Developer Guide

- [Overview](developer-guide/overview.md)
- [Agent Architecture](developer-guide/agent.md)
  - [Agent Ownership Boundaries](developer-guide/agent-ownership-boundaries.md)
  - [eBPF Runtime](developer-guide/ebpf-runtime.md)
  - [Kubernetes Runtime](developer-guide/kubernetes-runtime.md)
- [Rule Engine](developer-guide/rule-engine.md)
- [Manager Architecture](developer-guide/manager.md)
