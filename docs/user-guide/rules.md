# Rules

cicd-sensor rules evaluate events from CI/CD job runtime and use them for detection, collection, and correlation.

This section is written for SIRT and security teams who need to write real detection rules.
The expected operating model is to start with the standard rules bundled with cicd-sensor, then gradually add project-specific or organization-specific rules.

## Minimal rule

```yaml
rule_sets:
  - ruleset_id: acme/process
    rules:
      - rule_id: curl_exec
        rule_name: "curl executed"
        event_kind: process_exec
        condition: process.exec_path.endsWith("/curl")
        action: detect
```

This rule emits a Detection Log entry when `curl` is executed during a CI/CD job runtime.

## Reading order

| Page | Content |
| --- | --- |
| [RuleSet](rule-set.md) | Basic rule files, actions, targets, and `max_alerts` |
| [Event kinds](rule-event-kinds.md) | Fields and examples for event kinds such as `process_exec`, `network_connect`, and `file_open` |
| [CEL conditions](rule-cel-conditions.md) | Examples for conditions, strings, lists, ancestors, and IP ranges |
| [Correlation](rule-correlation.md) | Detections that combine multiple rule hits |
| [Rule modifiers](rule-modifiers.md) | Tuning existing rules with action overrides, exceptions, target excludes, and disable flags |
| [Rule development](rule-development.md) | Creating local rules, validating them, bundling them, and handing them to the manager |

## Important rules

- `rule_sets:` and `rule_modifiers:` cannot be placed in the same YAML document.
- Keep RuleSet files and modifier files separate.
- A bundle file is required when distributing rules with the manager.
- In GitHub-hosted runner standalone mode, repository-local `.cicd-sensor/rules/` can be used.
- When using the manager, repository-local rules are not used. Rules are fetched from the manager.
