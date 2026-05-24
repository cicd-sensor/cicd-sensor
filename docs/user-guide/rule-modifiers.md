# Rule modifiers

Rule modifiers add environment-specific exceptions and tuning without copying an existing RuleSet.

Use them to keep standard rules or organization-wide rules intact while disabling a rule for a specific project, changing an action, or adding exception conditions.

Rule modifiers are written under the top-level `rule_modifiers:` key.
Manage `rule_sets:` and `rule_modifiers:` as separate files.

## Minimal modifier

```yaml
rule_modifiers:
  - modifier_id: acme-prod-curl-exception
    targets:
      - ruleset_id: acme/network-tools
        rule_id: network_tool_exec
    add_exceptions: |
      process.exec_path.endsWith("/curl") &&
      process.argv.exists(arg, arg == "https://internal.example.com/health")
```

`modifier_id` identifies which modifier was applied in the Summary Log.

## Target rules

`targets` selects the rules a modifier applies to.

```yaml
targets:
  - ruleset_id: acme/network-tools
    rule_id: network_tool_exec
```

| field | Required | Meaning |
| --- | --- | --- |
| `ruleset_id` | yes | Target RuleSet |
| `rule_id` | no | Target rule. When omitted, the modifier applies to all rules in the RuleSet. |

## Modifier fields

| field | Purpose |
| --- | --- |
| `override_action` | Change the rule action to `detect`, `collect`, or `terminate` |
| `override_max_alerts` | Override the Detection Log limit. Allowed values are 1-100. |
| `add_exceptions` | Add exception conditions to the rule |
| `add_target_exclude` | Add entries to the rule's `target.exclude` |
| `disable` | Disable the target rule |

## Override action

Use this when you want to change how a rule is displayed or handled as `detect`, `collect`, or `terminate`.
Both `detect` and `collect` are emitted to the Detection Log, but they appear as different actions in reports and logs.

```yaml
rule_modifiers:
  - modifier_id: acme-collect-network-tool
    targets:
      - ruleset_id: acme/network-tools
        rule_id: network_tool_exec
    override_action: collect
```

## Add exceptions

`add_exceptions` is appended to the existing exceptions of the target rule.
Events where the condition evaluates to true are excluded from that rule's hits.

```yaml
rule_modifiers:
  - modifier_id: acme-known-healthcheck
    targets:
      - ruleset_id: acme/network-tools
        rule_id: network_tool_exec
    add_exceptions: |
      process.exec_path.endsWith("/curl") &&
      process.argv.exists(arg, arg == "https://internal.example.com/health")
```

This lets you keep the base rule unchanged and isolate environment-specific exceptions in a modifier.

## Add target exclude

Use this when a rule should not apply to a specific project.

```yaml
rule_modifiers:
  - modifier_id: acme-ignore-legacy-project
    targets:
      - ruleset_id: acme/network-tools
    add_target_exclude:
      - provider_host: github.com
        path: acme/legacy
```

`path` uses prefix matching.

## Disable rule

This fully disables the target rule.
First check whether `add_exceptions` or `add_target_exclude` can narrow the rule enough; use `disable` only when the rule is not needed.

```yaml
rule_modifiers:
  - modifier_id: acme-disable-noisy-rule
    targets:
      - ruleset_id: acme/network-tools
        rule_id: network_tool_exec
    disable: true
```
