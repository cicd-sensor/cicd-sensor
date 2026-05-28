# Baseline Rules

Baseline Rules are the standard detection rules provided by cicd-sensor.
They are maintained with current CI/CD supply-chain attack patterns in mind and are meant to be applied before project-specific or organization-specific rules.

The operating model is baseline first, customization second.
Most users should start with the baseline rule set, then add custom RuleSets or RuleModifiers only where their environment needs additional coverage or tuning.

## Default-on baseline

Baseline Rules are applied by default in every supported deployment mode.
Whether you run cicd-sensor on GitHub-hosted runners, self-hosted runners, or through Manager, each monitored runtime should start from the latest cicd-sensor baseline.

That keeps baseline detection coverage updated without requiring every repository to copy or maintain the rule set by hand.

Disable the baseline only when you want to opt out of standard detections.
In GitHub-hosted standalone mode, set `disable_baseline_rules: true` in `.cicd-sensor/config.yaml`.
In manager mode, set `disable_baseline_rules: true` in `manager.yaml`; project-side action or `project start` settings cannot override the manager's baseline policy.

## How to customize

Custom rules do not replace the baseline by default.
Use them to add organization-specific or repository-specific detections.

Use RuleModifiers when you want to tune baseline behavior.
This keeps your deployment aligned with future baseline updates while still letting you adjust local policy.

## Where to see the shipped rules

This page describes the operating model, not every individual baseline rule.
The source of truth for shipped rules is the [`rules/` directory in the cicd-sensor repository](https://github.com/cicd-sensor/cicd-sensor/tree/main/rules) and the released baseline rules artifact.
