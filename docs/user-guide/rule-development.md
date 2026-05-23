# Rule development

Create local rules as separate RuleSet files and RuleModifier files.

```yaml
rule_sets:
  - ruleset_id: acme/process
    rules:
      - rule_id: curl_exec
        event_kind: process_exec
        condition: process.exec_path.endsWith("/curl")
        action: collect
```

```text
rules/
|-- acme-rule-set.yaml
`-- acme-modifiers.yaml
```

Putting `rule_sets:` and `rule_modifiers:` in the same YAML document is a validation error.

## Validate

During development, validate the directory.

```sh
cicd-sensorctl rule validate rules/
```

You can also validate a single file.

```sh
cicd-sensorctl rule validate rules/acme-rule-set.yaml
```

## Bundle

For deployment, create a bundle file.

```sh
cicd-sensorctl rule bundle --input-dir rules --output-file rules.yaml
cicd-sensorctl rule validate rules.yaml
```

A bundle can contain both `rule_sets:` and `rule_modifiers:`.

## Local rule handoff

In GitHub-hosted runner standalone mode, repository-local `.cicd-sensor/rules/` can be used.

```text
repo
`-- .cicd-sensor/
    |-- config.yaml
    `-- rules/
        |-- acme-rule-set.yaml
        `-- acme-modifiers.yaml
```

When using local rules from the project, validate them before execution.

```sh
cicd-sensorctl rule validate .cicd-sensor/rules/
```

## Inspect runtime behavior on GitHub-hosted runners

When iterating on rules on a GitHub-hosted runner in standalone mode, set `enable-debug: true` on the action.
This starts the agent in debug mode and uploads a debug artifact that includes the Runtime Telemetry Log, so you can see exactly which events your rules observe without setting up a manager.

```yaml
    steps:
      - uses: cicd-sensor/cicd-sensor-action@0a8e3cadda4a9bb894eabd1a1960308cc7a5a5aa # v0.0.17
        with:
          enable-debug: true
```

This is the lightest path to confirm that a new rule matches the events you expect during development.

## Manager handoff

A bundle is required when using rules with the manager.
The manager receives the bundle file path through `--rules-file` or `CICD_SENSOR_MANAGER_RULES_FILE`.

```sh
cicd-sensorctl rule bundle --input-dir /etc/cicd-sensor/rules --output-file /etc/cicd-sensor/rules.yaml
cicd-sensorctl rule validate /etc/cicd-sensor/rules.yaml

export CICD_SENSOR_MANAGER_CONFIG_FILE=/etc/cicd-sensor/manager.yaml
export CICD_SENSOR_MANAGER_RULES_FILE=/etc/cicd-sensor/rules.yaml
cicd-sensor-manager
```

Do not put a `rules:` list inside `manager.yaml`.
Rule handoff is explicit at manager startup through `--rules-file <path>` or `CICD_SENSOR_MANAGER_RULES_FILE`.
