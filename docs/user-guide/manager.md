# Manager

cicd-sensor-manager is the component for operating cicd-sensor across multiple runners and projects.

The manager is the central point for config delivery, rule delivery, log ingest, and output routing.
Agent-to-manager communication uses the gRPC-based Connect protocol, and request / response types are defined with Protocol Buffers.

```mermaid
flowchart LR
    AGENT["cicd-sensor Agent"]
    MANAGER["cicd-sensor-manager"]
    CLOUD["Cloud Outputs<br/>S3 / GCS / Pub/Sub"]
    SIEM["SIEM"]

    AGENT -->|"FetchConfig<br/>Connect / Proto"| MANAGER
    AGENT -->|"IngestLog<br/>Connect / Proto"| MANAGER
    MANAGER -->|"Store / Stream"| CLOUD
    CLOUD --> SIEM

    classDef cicdSensor fill:#ecfdf5,stroke:#0f766e,color:#134e4a,stroke-width:1.5px;
    class AGENT,MANAGER cicdSensor
```

## When to use it

Use the manager for operations such as:

- Running a Self-hosted Machine Runner fleet.
- Distributing organization-wide standard rules or custom rules.
- Aggregating Detection Logs and Runtime Telemetry Logs into a SIEM or data lake.
- Keeping per-job evidence centrally for incident response.
- Avoiding cloud credentials on runner hosts.

For a first test in a single project, start with standalone GitHub-hosted runner usage.

## Deployment model

cicd-sensor-manager is a stateless config server and log router.
It does not require a persistent database or local queue. Replicas with the same config, rule bundle, tokens, and cloud credentials can be scaled horizontally.

For production, prefer running the manager as a container or serverless workload on cloud services instead of manually placing it on a VM.
This keeps it stateless, easy to scale, and close to the cloud-side outputs it writes to.

| Target | Notes |
| --- | --- |
| AWS Lambda | Uses a Lambda adapter image. A Lambda image that includes `public.ecr.aws/awsguru/aws-lambda-adapter` is provided. AWS only pulls from its own container registry (ECR), so mirror the `ghcr.io` image to ECR or push the image there directly. |
| ECS / Fargate | Uses the standard manager container image. AWS only pulls from its own container registry (ECR), so mirror the `ghcr.io` image to ECR or push the image there directly. Pass config / rules / tokens through file mounts, secrets, or environment variables. |
| Kubernetes | Run it as a Deployment with Service / Ingress. Pass config / rules through ConfigMap, Secret, or mounted volume. |
| Cloud Run | Uses the standard manager container image. Use service accounts / Workload Identity for GCS and Pub/Sub integration. Cloud Run only pulls from Google's container registry (Artifact Registry), so mirror the `ghcr.io` image to Artifact Registry or push the image there directly. |

Public container images are distributed through GitHub Packages.

| Image | Purpose |
| --- | --- |
| `ghcr.io/cicd-sensor/cicd-sensor-manager` | Standard deployment for ECS, Kubernetes, Cloud Run, and similar targets |
| `ghcr.io/cicd-sensor/cicd-sensor-manager-lambda` | Deployment with the AWS Lambda adapter |

See [cicd-sensor GitHub Packages](https://github.com/orgs/cicd-sensor/packages?repo_name=cicd-sensor) for the package list.

The manager does not terminate TLS directly.
Design HTTPS / TLS, authentication boundaries, and private network exposure with cloud-side components such as a load balancer, ingress, API Gateway, service mesh, or private network.

## Network requirements

Allow outbound HTTPS from the manager to the following hosts.

| Host | Purpose |
| --- | --- |
| `ghcr.io` | Fetch baseline rule bundles |
| `quay.io` | Fetch baseline rule bundles |
| `registry.gitlab.com` | Fetch baseline rule bundles |
| `tuf-repo-cdn.sigstore.dev` | Fetch the Sigstore root certificates used for baseline rule signature verification |

When using Manager, Agents do not connect to these hosts directly.
Agents connect to the Manager, and the Manager fetches and verifies baseline rules.

## Startup files

The manager reads a startup config file and an optional rule bundle file.
Their file locations can be specified by flags or environment variables.

| File | Flag | Environment variable | Required |
| --- | --- | --- | --- |
| manager config | `--config-file /etc/cicd-sensor/manager.yaml` | `CICD_SENSOR_MANAGER_CONFIG_FILE=/etc/cicd-sensor/manager.yaml` | yes |
| rule bundle | `--rules-file /etc/cicd-sensor/rules.yaml` | `CICD_SENSOR_MANAGER_RULES_FILE=/etc/cicd-sensor/rules.yaml` | no |

When both a flag and an environment variable are set, the flag wins.
If neither `--rules-file` nor `CICD_SENSOR_MANAGER_RULES_FILE` is set, the manager starts without a custom rule bundle.

```sh
export CICD_SENSOR_MANAGER_CONFIG_FILE=/etc/cicd-sensor/manager.yaml
export CICD_SENSOR_MANAGER_RULES_FILE=/etc/cicd-sensor/rules.yaml
export CICD_SENSOR_MANAGER_TOKEN=sk_cs_...

cicd-sensor-manager
```

## Manager token

Manager authentication uses bearer tokens.
Do not write tokens into the config file; pass them through environment variables or token files.

Generate a token with `cicd-sensorctl`.

```sh
cicd-sensorctl token generate
```

Manager side:

```sh
export CICD_SENSOR_MANAGER_TOKEN=sk_cs_...
cicd-sensor-manager \
  --config-file /etc/cicd-sensor/manager.yaml \
  --rules-file /etc/cicd-sensor/rules.yaml
```

Agent side:

```sh
export CICD_SENSOR_MANAGER_TOKEN=sk_cs_...
cicd-sensor agent start \
  --provider github \
  --runner machine \
  --manager-url https://cicd-sensor-manager.example.com
```

For rotation, the manager can accept up to two tokens.
With environment variables, use `CICD_SENSOR_MANAGER_TOKEN` and `CICD_SENSOR_MANAGER_TOKEN_2`.
With token files, specify `--manager-token-file` up to two times.

## manager.yaml

Minimal config that actually persists logs. Defines one S3 sink and routes
all three log kinds to it:

```yaml
bind:
  address: "0.0.0.0"
  port: 8080

default_max_alerts_per_rule: 10

sinks:
  s3-out:
    type: s3
    uri: s3://cicd-sensor-prod/cicd-sensor/
    region: ap-northeast-1

logs:
  job_result_log:
    sink: s3-out
  job_detection_log:
    sink: s3-out
  job_runtime_telemetry_log:
    sink: s3-out
```

`bind` is optional. Omitted or empty values fall back to `address: "0.0.0.0"` (listen on all interfaces) and `port: 8080`. `port` must be in 0–65535.
`default_max_alerts_per_rule` is optional and uses the same meaning as project config: it sets the default Detection Log limit for rules that do not set `max_alerts`.

For richer routing (per-log-kind destinations, multiple sinks), see
[Log routing](#log-routing).

| Setting | Purpose |
| --- | --- |
| `bind.address` | Listen address. Defaults to `0.0.0.0`. |
| `bind.port` | Listen port. Defaults to `8080`. |
| `default_max_alerts_per_rule` | Default per-rule Detection Log limit. Use 1-100 to set a value; omit it or set 0 to use the system default. |
| `sinks` | Physical log destinations. |
| `logs` | Mapping from log `log_type` to one sink. |

## Log routing

When logs are aggregated through the manager, define `sinks` and `logs`.
`sinks` define physical destinations, and `logs` maps each log kind to one sink.

```yaml
sinks:
  gcs-result:
    type: gcs
    uri: gs://cicd-sensor-prod/cicd-sensor/

  pubsub-detection:
    type: pubsub
    project_id: security-prod
    topic: cicd-sensor-detection-log

  pubsub-telemetry:
    type: pubsub
    project_id: security-prod
    topic: cicd-sensor-runtime-telemetry-log

logs:
  job_result_log:
    sink: gcs-result
  job_detection_log:
    sink: pubsub-detection
  job_runtime_telemetry_log:
    sink: pubsub-telemetry
```

Supported log kinds:

| Log kind | Purpose |
| --- | --- |
| `job_result_log` | Job summary generated at finalize time |
| `job_detection_log` | Detection stream for rule hits |
| `job_runtime_telemetry_log` | Runtime telemetry for incident response and forensics |

Each log kind takes one `sink`.
Use this mapping to choose patterns such as storing all logs in one GCS destination, streaming only Detection Logs to Pub/Sub, or retaining Runtime Telemetry Logs in object storage.

### Sink settings

| Sink type | Required settings | Notes |
| --- | --- | --- |
| `gcs` | `uri` | `uri` is a `gs://...` object-storage URI. Include any desired object key path in the URI. |
| `pubsub` | `project_id`, `topic` | Publishes one plain JSON record per message. |
| `s3` | `uri`, `region` | `uri` is an `s3://...` object-storage URI. Include any desired object key path in the URI. |

Store logs in GCS:

```yaml
sinks:
  gcs-prod:
    type: gcs
    uri: gs://cicd-sensor-prod/cicd-sensor/

logs:
  job_result_log:
    sink: gcs-prod
  job_detection_log:
    sink: gcs-prod
  job_runtime_telemetry_log:
    sink: gcs-prod
```

Send logs to Pub/Sub:

```yaml
sinks:
  pubsub-detection:
    type: pubsub
    project_id: security-prod
    topic: cicd-sensor-detection-log

  pubsub-telemetry:
    type: pubsub
    project_id: security-prod
    topic: cicd-sensor-runtime-telemetry-log

logs:
  job_detection_log:
    sink: pubsub-detection
  job_runtime_telemetry_log:
    sink: pubsub-telemetry
```

For GCS / Pub/Sub authentication, the manager process uses standard Google Cloud Application Default Credentials.
On GKE / GCE, grant access with Workload Identity or an attached service account. In other environments, use the standard runtime mechanism such as `GOOGLE_APPLICATION_CREDENTIALS`.
Do not write service account keys or credential paths into `manager.yaml`.

Cloud credentials for S3 / GCS / Pub/Sub are held only by the manager process.
The Agent does not receive cloud credentials.
