# Rename progress

Tracks the pre-release sweep: drop `job_` prefix, `kind` → `type`, `telemetry` → `event` (runtime log).
Plan: `/Users/rung/.claude/plans/rules-environment-dreamy-cray.md`.

## Phases

- [x] Phase 0: progress file initialized
- [x] Phase 1: proto edits (keep file names)
- [x] Phase 2: `make generate-proto`
- [x] Phase 3: `internal/logkind/` → `internal/logtype/`
- [x] Phase 4: file renames (Go + proto + docs) + re-generate
- [x] Phase 5: Go identifier replacements (go build, vet, test all clean)
- [x] Phase 6: docs + YAML sweep (residual scan empty; 3 integration tests dependent on republished baseline rules fail as expected)
- [x] Phase 7: cicd-sensor-action repo (src + tests + action.yml + README updated; dist rebuilt; tests pass; NOT committed yet)
- [x] Phase 8: final verification — gofmt clean, go vet clean, all unit tests pass, make rules-validate OK, residual grep = 0 in both repos
- [x] Phase 9: per-occurrence audit of result / telemetry / kind (incl. projectresult/resultdoc)

## Phase 9: per-occurrence audit findings + fixes

### result derived from old job_result_log → renamed to summary
- Variable `resultLog` → `summaryLog` in cmd/cicd-sensorctl/{report_attest,report_html,report_stepsummary}.go
- Variable `resultIn` → `summaryIn` in jobregistry/finalize.go
- Variable `resultRecords` → `summaryRecords`
- Logger key `result_log_emit_failed` → `summary_log_emit_failed`
- Test messages "job result log/output/entries/drops/write" → "summary log/output/..."
- "result.json" temp file → "summary.json"
- Socket.go comment "result log needs" → "summary log needs"

### Kept as legitimate (HTML report = user-facing "result")
- `cicd-sensor project result` CLI subcommand + `/v1/project/result` HTTP endpoint
- `internal/agent/projectresult/`, `internal/resultdoc/` package names
- `resultdoc.Result{NoAlert,Detected,Terminated}` constants (job verdict)
- `ResultSummary.Result` field (job verdict)
- `resultRuleType`, `resultProcessSummary` helper names (convert into result document)
- Generic `var result struct{...}` HTTP response decode in tests

### telemetry → runtime event renames
- Test file `runtime_telemetry_test.go` → `runtime_event_test.go`
- All `TestXxxRuntimeTelemetry*` → `TestXxxRuntimeEvent*`
- Helpers `recordingRuntimeTelemetryOutput`, `attachRecordingRuntimeTelemetryOutput`, `writeRuntimeTelemetryPayload`, `runtimeTelemetryEntries`, `readDebugRuntimeTelemetryEntry` → RuntimeEvent versions
- Sink constants `{gcs,pubsub,s3}RuntimeTelemetryFlush{Bytes,Seconds}` → RuntimeEvent
- Test fixture strings, mermaid diagram labels, manager.yaml example sink/topic names
- HTML/Pub-sub example: `pubsub-telemetry` → `pubsub-runtime-event`, topic `cicd-sensor-runtime-telemetry-log` → `cicd-sensor-runtime-event-log`
- Docs prose: "emitted as telemetry", "telemetry / correlation inputs", "Runtime Telemetry for incident response", etc.
- attestation.go comments: "non-enforcing telemetry" → "non-enforcing collection", "telemetry-style hits" → "collection-style hits"
- rule descriptions in testevent.yaml: "for X telemetry." → "for X runtime events."

### Kept telemetry (generic eBPF usage)
- docs/user-guide/self-hosted-install.md:56 "process telemetry" (generic eBPF, not log-kind specific)

### kind → type renames (this round, beyond logkind/ScopeKind)
- CLI help: "Runner kind." → "Runner type." (agent.go)
- Error: `ErrScopeTypeMismatch = errors.New("scope kind mismatch")` → "scope type mismatch" + comment update
- Test fn names: `TestStartJobLogsIgnoresDisabledKind` → `...DisabledType`, `TestStartJobLogsUsesOneWorkerPerKind` → `...PerType`
- Test prose: "dropped records for unknown kind", "scope kind:", "after kind mismatch" → type
- Test JSON payload `{"kind":"detection"}` → `{"type":"detection"}` (proto field is now `type`)
- Test rule ID string `"kind-mismatch"` → `"type-mismatch"`
- joblogs struct fields & function params: `kind managerv1.LogType` → `logType`, `kind jobcontext.ScopeType` → `scopeType` (manager_worker.go, manager_output.go, manager_job_logs.go, testing.go)
- resultdoc test: `TestJobEventSummaryForReport_KeepsRunnerKindOutsideMetadata` → `...RunnerType...`, "metadata.runner_kind" prose → "metadata.runner_type"

### Phase 9.5 follow-up: broader audit caught embedded CamelCase + test names

- README.md / docs/index.md: "like Job Result, Detection, and Runtime Event" → "like Summary, Detection, and Runtime Event Logs"
- attestation-predicate.md: "final job result summary" → "final job summary"
- Test fn names embedded with `JobResultLog` / `JobDetectionLog` / `JobRuntimeTelemetryLog` substrings (boundary-less catchall): `TestMarshalJobResultLogEntry*`, `TestManagerJobLogsEmitAndCloseJobResultLog`, `TestJobScopeStateEmitJobResultLog_FlushesFinalRecord`, `assertJobResultOutputSettings`, `TestEvaluateEvent_ExceptionsAndKindsSkipHits`, `TestEvaluateEvent_FileKindHits`, `TestEvaluateEvent_FileMutationKindsEndToEnd`, `TestManagerJobLogsNoOpWhenLogKindsAreNotConfigured`, `TestCELInputEventFromRecordFileMutationKinds`, `TestCELInputEventFromRecordEventKindPayloads` — all renamed
- celengine API: `EnvForKind` method → `EnvForType`, parameters `kind jobevent.Type` → `eventType`
- Test struct field `kind jobevent.Type` → `eventType` (env_test.go, exists_macro_test.go, validate_test.go) + accessor renames
- finalize_output_test.go: `gotKinds` → `gotTypes`, loop var `kind` → `logType`, error message "kind=" → "type="
- merge_test.go: `testRule(id, kind jobevent.Type, ...)` → `eventType` param
- Reverted MergeWarning.Kind json tag from `"type"` back to `"kind"` (Go field name stayed `Kind` per user choice; my earlier blanket sweep had accidentally retagged it)

### Kept kind (out of scope per user decision)
- `kerneltracker.SampleKind*` family + `sample.Kind` accesses (~100 occurrences) — eBPF sample categorization
- `MergeWarning.Kind` field (~22 occurrences) — rule merge warning categorization
- `costWarning.Kind` field (~7 occurrences) — rule cost warning categorization

## Phase 10: Enumerate-then-classify exhaustive verifier (zero-miss guarantee)

Built `/tmp/verify_rename.py` with all enumerated old-form variants + explicit keep-list.

### Misses found and fixed
- `cmd/cicd-sensorctl/testdata/sample-result-log.json` → `sample-summary-log.json` + content `event_kind` → `event_type` (orphaned fixture, no callers, but renamed for consistency)
- `internal/agent/jobscope/manager_logs_test.go`: helper `jobResultEntries` → `summaryEntries`
- `internal/ctl/report/attestation_test.go`: `TestAttestationPredicate_OmitsEmptyRunnerKind` / `KeepsRunnerKindWhenSet` → `RunnerType`
- `internal/ctl/report/report.tmpl.html`: `d.runner_kind` → `d.runner_type` (HTML template field)
- `internal/manager/collector_service.go`: `outputLogKind()` function → `outputLogType()`, var `logKind` → `logType`, param `kind` → `logType`
- `internal/manager/collector_service_test.go`: `unsupportedLogKind` → `unsupportedLogType`
- `cmd/cicd-sensorctl/report_*_test.go`: helper `sampleResultLog()` → `sampleSummaryLog()`
- Attestation predicate URL `https://cicd-sensor.github.io/runner-kind` → `runner-type` (attestation.go + attestation_test.go + docs/user-guide/attestation-predicate.md)
- `cicd-sensor-action/test/main.test.js`: test description "uses JobLogContext flag names" → "LogContext flag names"

### Verifier final result
- **OK — 0 hits, all classified as keep**
- Covers both repos (cicd-sensor + cicd-sensor-action)
- Covers all extensions: .go .proto .md .yaml .yml .html .tmpl .js .mjs .ts .json .sh .toml
- Skips: vendor/, .git/, node_modules/, internal/proto/, bpf/generated/, dist/main, dist/post, book/

### Functional verification
- `gofmt -l ./...` empty ✅
- `go build ./...` clean ✅
- `go vet ./...` clean ✅
- `go test ./...` ✅ (3 baseline-fetch integration tests fail as expected — external state)
- `make rules-validate` OK ✅
- cicd-sensor-action `npm test` 22/22 pass ✅

## Outstanding (post-rename)

1. Re-publish baseline rule bundles to ghcr.io / quay.io / registry.gitlab.com with new `event_type` schema. Until then, these 3 integration tests fail:
   - `internal/agent/managerclient.TestManagerIntegration_FetchConfig_EndToEnd`
   - `internal/agent/managerclient.TestManagerIntegration_FetchConfig_EmptyBundle`
   - `internal/manager.TestConfigService_FetchConfig_ReloadsLocalRulesOnChange`
2. Commit decisions (await user authorization per `feedback_commit_authorization`):
   - cicd-sensor: large rename diff
   - cicd-sensor-action: src + dist + action.yml + README changes

## Untouched (by design)

- `internal/agent/projectresult/` (HTML report)
- `internal/resultdoc/` (HTML report)
- `vendor/`

## Notes

(populate as we hit edge cases or unexpected references)
