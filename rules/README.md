# Baseline Rules

This directory contains the **Baseline Rules** shipped with cicd-sensor.

Rules placed here and bundled by the release pipeline are published as the
`cicd-sensor-rules` OCI artifact and used for detection on every cicd-sensor
deployment.

## Lifecycle

`cicd-sensorctl rule bundle` combines rule files in a directory into a
single ruleset, which the release pipeline publishes. When the agent begins
monitoring a CI run, it fetches that latest released ruleset and applies it
for the duration of that run.

## Validation

Validate locally:

```sh
make rules-validate          # parse + CEL compile + schema
make rules-bundle-validate   # also bundle and re-validate the bundle
```

The release flow refuses to publish a bundle that fails either step.
