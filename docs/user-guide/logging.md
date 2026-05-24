# Logging

cicd-sensor logs are delivered as gzip-compressed JSONL batches.
The log schema is maintained in Protocol Buffers, and the source of truth is [`proto/cicd_sensor/log/v1`](https://github.com/cicd-sensor/cicd-sensor/tree/main/proto/cicd_sensor/log/v1).

With manager delivery, the Agent sends these JSONL batches to the manager.
The manager delivers each batch to the configured sink.

## Log types

Each log entry's `log_type` field uses the dotted form `cicd_sensor.<short>`. This is the routing key for downstream consumers. Manager-side configuration keys and sink object paths use the short form (`summary`, `detection`, `runtime_event`).

| `log_type` value | Short name | Purpose | Timing |
| --- | --- | --- | --- |
| `cicd_sensor.summary` | `summary` | Final job summary. Entry point for reviewing runtime results per job. | Generated when the job finalizes. |
| `cicd_sensor.detection` | `detection` | Per-rule-hit log for real-time detection and triage. Includes both `detect` and `collect` actions. | Streamed while the job is running. |
| `cicd_sensor.runtime_event` | `runtime_event` | Detailed runtime events for incident response and forensics. | Streamed while the job is running. |

## Common fields

Every log entry carries these top-level fields, regardless of log type.

| Field | Description |
| --- | --- |
| `timestamp` | UTC, RFC 3339 |
| `log_type` | One of the log types listed above (e.g. `cicd_sensor.summary`) |
| `service_name` | Identifies the emitter of this log. Currently always `cicd-sensor` |
| `service_version` | Agent build version (e.g. `v0.0.27`) |
| `schema_version` | Schema version of this `log_type`. Bumped on breaking changes |
| `log_id` | UUID(v7) per log row |
| `scope` | `host` for self-hosted configuration, `project` for GitHub Action invocations |
| `runner_type` | Runner type, such as `machine` |

## Job context

Every log entry includes a `job` object.
Use these fields to group logs for the same CI job.
Other fields add useful context for search, reports, and triage.

| Field | Description |
| --- | --- |
| `provider` | `github` or `gitlab` |
| `provider_host` | `github.com`, `gitlab.com`, or a self-managed host |
| `project_path` | Repository / project path |
| `job_link` | Job URL in the provider |
| `commit_sha` | Target commit |
| `ref_name` | Branch or tag |
| `trigger` | CI event or trigger |
| `actor_id` | Provider actor ID |
| `actor_name` | Provider actor name |
| `github_run_id` | GitHub Actions run ID |
| `github_job` | GitHub Actions job id/key from `GITHUB_JOB` |
| `github_run_attempt` | GitHub Actions run attempt |
| `github_runner_tracking_id` | GitHub runner tracking ID |
| `github_workflow_ref` | GitHub Actions workflow file ref |
| `github_workflow_sha` | GitHub Actions workflow file commit SHA |
| `github_workflow` | GitHub Actions workflow name |
| `gitlab_job_id` | GitLab CI job execution ID |
| `gitlab_job_name` | GitLab CI job name |
| `gitlab_config_ref_uri` | GitLab CI config provenance URI |

## Runtime event format

Both the `detection` and `runtime_event` logs include an `event` object.
This object describes the runtime behavior that triggered a rule hit or was emitted as a runtime event.

| Field | Description |
| --- | --- |
| `id` | Runtime event UUID(v7). Unique per captured event |
| `type` | `process_exec`, `network_connect`, `file_open`, `domain`, and other event types |
| `tags` | Tags attached to the event |
| `process` | PID, executable path, argv, and ancestor processes |
| event-specific payload | Fields for the specific event type, such as network destination, file path, or domain |

### argv output sanitization

`process.argv` and `process.ancestors.argv` can contain credentials.
Rules are evaluated against the captured process context, but logs and reports use an output-sanitized form.

In output, argv values that look like tokens, passwords, secrets, credential material, or auth headers are replaced with `<redacted>`.
Long argv values are shortened and marked with `<truncated, N bytes>`.

This means a rule can match full argv content even when the corresponding log entry shows only a redacted or shortened value.

## How to use the logs

| Question | First log to check |
| --- | --- |
| What happened across the job? | `summary` |
| Which rules hit? | `detection` |
| Which process / network / file events happened around a detection? | `runtime_event` |
| How do I follow a detection through the rest of the job? | Join the detection's `job` fields to `runtime_event` and read by `timestamp` to trace the job's full activity. |

When building a compatible log consumer, use the linked proto schema as the exact field reference.

For build verification rather than detailed log consumption, see [Attestation predicate](attestation-predicate.md).
