# Correlation

Correlation rules combine hit counts from other rules.

They are useful when a single event is only an investigative signal, but multiple signals in the same job form a stronger detection.
For example, `curl` execution alone may be normal, and a credential file read alone may need context, but `curl` execution plus credential file access in the same job is much more important.

Mark primitive signals as `collect`, then add a correlation rule with `detect` when the combination appears.
`collect` is also emitted to `detection_log`, so you can review the primitive signals while treating only the stronger combination as a detection.

```yaml
rule_sets:
  - ruleset_id: acme/supply-chain
    rules:
      - rule_id: suspicious_network_tool
        rule_name: "suspicious network tool"
        event_type: process_exec
        condition: process.exec_path.endsWith("/curl") || process.exec_path.endsWith("/wget")
        action: collect

      - rule_id: credential_file_read
        rule_name: "credential file read"
        event_type: file_open
        condition: is_read && path.endsWith(".npmrc")
        action: collect

      - rule_id: network_tool_and_credential
        rule_name: "network tool and credential access"
        type: correlation
        condition: |
          rule.suspicious_network_tool.total_count >= 1 &&
          rule.credential_file_read.total_count >= 1
        action: detect
```

Correlation rules reference rules in the same RuleSet.
The available field is `total_count`.

In a correlation `condition`, use `rule.<rule_id>.total_count`.

```yaml
condition: |
  rule.suspicious_network_tool.total_count >= 1 &&
  rule.credential_file_read.total_count >= 1
```

The default pattern is to keep broad primitive rules as `collect` in the Detection Log, then add a correlation rule that emits a stronger `detect` signal.

## Adding counts

`+` and `-` are allowed in correlation conditions when you want to combine hit counts from multiple primitive rules.
`*`, `/`, and `%` are rejected.

```yaml
condition: |
  rule.suspicious_network_tool.total_count +
  rule.credential_file_read.total_count >= 5
```

## Counting unique categories with presence bits

When you want a correlation to fire only when multiple distinct categories of primitive rule fire — rather than when one noisy rule fires many times — convert each `total_count` to a presence bit (`0` or `1`) with the ternary operator and add the bits together.

```yaml
- rule_id: npm_install_multi_secret_surface
  type: correlation
  condition: |
    (
      (rule.npm_install_cloud_secret_surface.total_count >= 1 ? 1 : 0) +
      (rule.npm_install_registry_secret_surface.total_count >= 1 ? 1 : 0) +
      (rule.npm_install_vcs_secret_surface.total_count >= 1 ? 1 : 0) +
      (rule.npm_install_ai_devtool_secret_surface.total_count >= 1 ? 1 : 0)
    ) > 1
  action: detect
```

Adding raw `total_count` values and adding presence bits answer different questions.
Raw addition asks "how many total hits happened across these rules?"
Presence-bit addition asks "how many distinct rule categories appeared?"

If you want unique-category counting, wrap each reference in `total_count >= 1 ? 1 : 0` first.
Otherwise, repeated hits from one category can dominate the threshold.
