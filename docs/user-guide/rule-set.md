# RuleSet

A RuleSet is a group of rules that evaluate events from CI/CD job runtime.
RuleSets are written under the top-level `rule_sets:` key.

## Minimal RuleSet

```yaml
rule_sets:
  - ruleset_id: acme/basic
    rules:
      - rule_id: curl_exec
        rule_name: "curl executed"
        event_type: process_exec
        condition: process.exec_path.endsWith("/curl")
        action: detect
        tags:
          severity: medium
          category: execution
```

`condition` is written in CEL.
See [CEL conditions](rule-cel-conditions.md) for details.

## Rule identity

`ruleset_id` must be unique across all sources.
`rule_id` must be unique within the same RuleSet.

Correlation rules reference rules as `rule.<rule_id>.total_count`, so `rule_id` must be valid as a CEL identifier.

Allowed characters:

- ASCII letters.
- Digits.
- Underscore.

`rule_id` cannot start with a digit and cannot contain hyphens, spaces, or non-ASCII characters.
Use `rule_name` for the display name.

## Rule types

Normal rules evaluate runtime events directly.
Set `event_type` and `condition`; when an event matches the condition, the configured `action` is emitted.

```yaml
- rule_id: curl_exec
  event_type: process_exec
  condition: process.exec_path.endsWith("/curl")
  action: detect
```

Use a correlation rule when you want to combine multiple rule hits.
See [Correlation](rule-correlation.md) for details.

```yaml
- rule_id: network_tool_and_credential
  type: correlation
  condition: |
    rule.suspicious_network_tool.total_count >= 1 &&
    rule.credential_file_read.total_count >= 1
  action: detect
```

## Event rule fields

| Field | Required | Description |
| --- | --- | --- |
| `rule_id` | yes | ID unique within the RuleSet |
| `rule_name` | no | Display name shown in reports and logs |
| `event_type` | yes | Event type to evaluate, such as `process_exec`, `network_connect`, or `file_open` |
| `condition` | yes | CEL expression that returns bool |
| `action` | yes | `detect`, `collect`, or `terminate` |
| `tags` | no | Metadata such as severity or category |
| `target` | no | Repository / project scope where the rule applies |
| `max_alerts` | no | Maximum entries emitted to the Detection Log per job / rule |

## Actions

| action | Meaning | Detection Log |
| --- | --- | --- |
| `detect` | Record as a detection | emitted |
| `collect` | Record as a signal for investigation or correlation | emitted |
| `terminate` | Attempt to stop the job | emitted |

Today, the difference between `detect` and `collect` is how they are displayed in reports and logs.
Both are emitted to the Detection Log.

A useful pattern is to mark broad primitive signals as `collect`, then use a correlation rule to emit `detect` only when multiple conditions appear together.
This separates investigative signals from stronger alerts.
Future notification or alert-delivery features may give `detect` and `collect` different behavior.

## Target

`target` is used by the manager to control rule scope per repository when managing rules for multiple repositories centrally.

It can express rules that apply only to a specific repository, or organization-wide rules that exclude specific repositories.

```yaml
target:
  include:
    - provider_host: github.com
      path: acme/prod
  exclude:
    - path: acme/prod-legacy
```

When `include` is set, the rule applies only to matching repositories.
When `include` is omitted, all repositories are included.

`path` uses prefix matching.
If both include and exclude match, exclude wins.

## max_alerts

`max_alerts` limits how many entries a rule can emit to the Detection Log per job / rule.
Use it to prevent noisy rules from filling the log.

```yaml
max_alerts: 10
```

When omitted, the system default `10` is used.
