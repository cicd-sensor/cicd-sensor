---
name: False positive report
about: Report a rule detection on expected CI/CD activity
title: '[False positive] '
labels: bug
assignees: ''
---

## Detected rule

- Ruleset ID:
- Rule ID:
- Rule revision:
- Action: <!-- detect / terminate -->

## Expected activity

<!-- What command, tool, package, or workflow behavior triggered the rule? Why is it expected? -->

## Steps to reproduce

<!-- Provide the smallest workflow or command sequence that reproduces the detection. -->

1.
2.
3.

## Detection evidence

<!-- Paste the relevant detection entry or report excerpt, not the complete debug bundle. -->

```text
```

- [ ] I removed tokens, credentials, secrets, and other sensitive data from this report.

## Environment

- cicd-sensor version:
- Deployment: <!-- GitHub-hosted runner / Self-hosted Machine Runner / GitHub ARC / GitLab Runner -->
- Runner OS / architecture:
- Linux kernel: <!-- output of `uname -r` -->
- Relevant tool / package and version:

## Impact and workaround

<!-- Did the rule only report a detection, or did it terminate the job? Include any modifier or workaround currently used. -->

## Additional context

<!-- Related issues, logs, or other details that may help distinguish expected behavior from an attack. -->
