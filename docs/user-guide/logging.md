# Logging

cicd-sensor logs are delivered as gzip-compressed JSONL batches.
The log schema is maintained in Protocol Buffers, and the source of truth is [`proto/cicd_sensor/log/v1`](https://github.com/cicd-sensor/cicd-sensor/tree/main/proto/cicd_sensor/log/v1).

With manager delivery, the Agent sends these JSONL batches to the manager.
The manager delivers each batch to the configured sink.

## Log types

| Log type | Purpose | Timing |
| --- | --- | --- |
| `summary_log` | Final job summary. This is the entry point for reviewing runtime results per job. | Generated when the job finalizes. |
| `detection_log` | Per-rule-hit log for real-time detection and triage. Includes both `detect` and `collect` actions. | Streamed while the job is running. |
| `runtime_event_log` | Detailed runtime events for incident response and forensics. | Streamed while the job is running. |

## Common fields

Every log entry carries these top-level fields, regardless of log type.

| Field | Description |
| --- | --- |
| `timestamp` | UTC, RFC 3339 |
| `log_type` | One of the log types listed above |
| `schema_version` | Schema version of this `log_type`. Bumped on breaking changes |
| `agent_version` | Agent build version |
| `log_id` | UUID(v7) per log row |
| `scope` | `host` for self-hosted configuration, `project` for GitHub Action invocations |
| `runner_type` | Runner type, such as `machine` |

`summary_log` additionally carries `config_revision` — the manager config revision used for this job, or `(none)`.

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

Both `detection_log` and `runtime_event_log` include an `event` object.
This object describes the runtime behavior that triggered a rule hit or was emitted as a runtime event.

| Field | Description |
| --- | --- |
| `id` | Runtime event UUID(v7). Use it to join runtime events and detections. |
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
| What happened across the job? | `summary_log` |
| Which rules hit? | `detection_log` |
| Which process / network / file events happened around a detection? | `runtime_event_log` |
| How do I investigate the source event behind a SIEM alert? | Join `detection_log.event.id` with `runtime_event_log.event.id` |

When building a compatible log consumer, use the linked proto schema as the exact field reference.

For build verification rather than detailed log consumption, see [Attestation predicate](attestation-predicate.md).
