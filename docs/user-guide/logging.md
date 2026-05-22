# Logging

cicd-sensor logs are delivered as gzip-compressed JSONL batches.
The log schema is maintained in Protocol Buffers, and the source of truth is [`proto/cicd_sensor/log/v1`](https://github.com/cicd-sensor/cicd-sensor/tree/main/proto/cicd_sensor/log/v1).

With manager delivery, the Agent sends these JSONL batches to the manager.
The manager delivers each batch to the configured sink.

## Log kinds

| Log kind | Purpose | Timing |
| --- | --- | --- |
| `job_result_log` | Final job summary. This is the entry point for reviewing runtime results per job. | Generated when the job finalizes. |
| `job_detection_log` | Per-rule-hit log for real-time detection and triage. Includes both `detect` and `collect` actions. | Streamed while the job is running. |
| `job_runtime_telemetry_log` | Detailed runtime events for incident response and forensics. | Streamed while the job is running. |

## Job context

Every log entry includes a `job` object.
Use these fields to group logs for the same CI job.
Other fields add useful context for search, reports, and triage.

| Field | Description |
| --- | --- |
| `provider` | `github` or `gitlab` |
| `provider_host` | `github.com`, `gitlab.com`, or a self-managed host |
| `project_path` | Repository / project path |
| `runner_kind` | Runner kind, such as `machine` |
| `job_link` | Job URL in the provider |
| `github_run_id` | GitHub Actions run ID |
| `github_job` | GitHub Actions job id/key from `GITHUB_JOB` |
| `github_run_attempt` | GitHub Actions run attempt |
| `github_runner_tracking_id` | GitHub runner tracking ID |
| `gitlab_job_id` | GitLab CI job execution ID |
| `commit_sha` | Target commit |
| `ref_name` | Branch or tag |
| `trigger` | CI event or trigger |
| `actor_id` | Provider actor ID |
| `actor_name` | Provider actor name |
| `github_workflow_ref` | GitHub Actions workflow file ref |
| `github_workflow_sha` | GitHub Actions workflow file commit SHA |
| `github_workflow` | GitHub Actions workflow name |
| `gitlab_job_name` | GitLab CI job name |
| `gitlab_config_ref_uri` | GitLab CI config provenance URI |

Each log entry also includes `log_id`, `timestamp`, `scope`, and `config_revision`.
`log_id` is a UUID(v7) for each log row.

## Runtime event format

Both `job_detection_log` and `job_runtime_telemetry_log` include an `event` object.
This object describes the runtime behavior that triggered a rule hit or was emitted as telemetry.

| Field | Description |
| --- | --- |
| `id` | Runtime event UUID(v7). Use it to join telemetry and detections. |
| `kind` | `process_exec`, `network_connect`, `file_open`, `domain`, and other event kinds |
| `tags` | Tags attached to the event |
| `process` | PID, executable path, argv, and ancestor processes |
| event-specific payload | Fields for the specific event kind, such as network destination, file path, or domain |

`process.argv` and `process.ancestors.argv` are redacted for output.
Values that look like tokens, passwords, secrets, or auth headers are replaced with `<redacted>`.

## How to use the logs

| Question | First log to check |
| --- | --- |
| What happened across the job? | `job_result_log` |
| Which rules hit? | `job_detection_log` |
| Which process / network / file events happened around a detection? | `job_runtime_telemetry_log` |
| How do I investigate the source event behind a SIEM alert? | Join `job_detection_log.event.id` with `job_runtime_telemetry_log.event.id` |

When building a compatible log consumer, use the linked proto schema as the exact field reference.

For build verification rather than detailed log consumption, see [Attestation predicate](attestation-predicate.md).
