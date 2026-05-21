# Manager Architecture

The Manager is the server component that receives config fetch and log ingest requests from Agents.
Agent-to-manager communication uses the gRPC-based Connect protocol.
Request / response types are defined with Protocol Buffers, and the source of truth for the wire contract is `proto/cicd_sensor/manager/v1`.

Runtime event observation, rule merge, and rule evaluation are Agent responsibilities.
The Manager does not observe CI/CD runtime directly. It acts as the config / rule delivery and log delivery boundary.

## Protocol boundary

The Manager exposes two endpoints to Agents.

| Service | Method | Purpose |
| --- | --- | --- |
| `ConfigService` | `FetchConfig` | Agent fetches config, rule source, and output policy |
| `CollectorService` | `IngestLog` | Agent sends gzip-compressed JSONL log batches to the manager |

```mermaid
flowchart LR
    AGENT["cicd-sensor Agent"]

    subgraph MANAGER["cicd-sensor-manager"]
        CONFIG["ConfigService.FetchConfig<br/>config / rules / output policy"]
        COLLECTOR["CollectorService.IngestLog<br/>log batch ingest"]
    end

    S3["S3"]
    GCS["GCS"]
    PUBSUB["Pub/Sub"]

    AGENT -->|"Connect / Proto"| CONFIG
    AGENT -->|"Connect / Proto"| COLLECTOR
    COLLECTOR -->|"Store"| S3
    COLLECTOR -->|"Store"| GCS
    COLLECTOR -->|"Stream"| PUBSUB

    classDef cicdSensor fill:#ecfdf5,stroke:#0f766e,color:#134e4a,stroke-width:1.5px;
    classDef managerFrame fill:#ecfdf5,stroke:#0f766e,color:#134e4a,stroke-width:1.5px;
    classDef service fill:#ffffff,stroke:#94a3b8,color:#374151,stroke-width:1px;
    class AGENT cicdSensor
    class MANAGER managerFrame
    class CONFIG,COLLECTOR service
```

The management API is not defined yet.
If a UI or operator API becomes necessary, it should be designed separately around concrete consumers and use cases.

## Config and rule delivery

Agents fetch config and rules with `ConfigService.FetchConfig`.
In manager mode, repository-local `.cicd-sensor/config.yaml` and `.cicd-sensor/rules/` are not used.

The Manager reads startup config and rule bundle files.
File paths can be specified by CLI flags or environment variables, but the config / rules contents themselves are not expanded into environment variables.

Rule sources returned by the Manager are merged and compiled by the Agent.
The Manager holds the rule bundle, but it does not evaluate runtime events.

## Log ingest and outputs

Agents send Job Result Logs, Detection Logs, and Runtime Telemetry Logs to `CollectorService.IngestLog` as gzip-compressed JSONL batches.
The Manager delivers them to sinks such as S3, GCS, or Pub/Sub according to the routing policy for each log kind.

The Manager treats the log batch as the delivery unit.
It does not interpret runtime events or evaluate detections.

Cloud credentials are held only by the Manager process.
Agents do not receive cloud credentials.

## Design rules

- Treat the Manager as a stateless config server and log router.
- Replicas with the same startup config, rule bundle, tokens, and cloud credentials can scale horizontally.
- Authentication validates the bearer token on each request.
- Token and config reload is done by process restart.
- TLS is not terminated inside the Manager process. Termination belongs to Ingress, load balancer, service mesh, or private network infrastructure.
