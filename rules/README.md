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

## IOC Rules

`ioc.yaml` is reserved for high-confidence campaign indicators. It currently
contains one example IOC and is expected to grow as we add short-lived,
source-backed indicators that are too specific for the generic baseline rules.

## Validation

Validate locally:

```sh
make rules-test              # evaluate shipped rules against behavior cases
make rules-validate          # parse + CEL compile + schema
make rules-bundle-validate   # also bundle and re-validate the bundle
```

The release flow refuses to publish a bundle that fails either step.
