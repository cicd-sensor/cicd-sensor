package jobscope

import (
	"context"
	"log/slog"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/joblogs"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

type JobResultLogInputs struct {
	Identity   jobcontext.JobIdentity
	Metadata   jobcontext.JobMetadata
	RunnerKind string
	StartedAt  time.Time
}

func (s *JobScopeState) EmitJobResultLog(ctx context.Context, in JobResultLogInputs, reason string, finalizedAt time.Time) error {
	if s == nil || !s.managerJobLogs.HasJobResultLog() {
		return nil
	}
	payload, err := joblogs.MarshalJobResultLogEntry(joblogs.JobResultLogInput{
		ScopeLogContext: joblogs.ScopeLogContext{
			Identity:       in.Identity,
			Metadata:       in.Metadata,
			RunnerKind:     in.RunnerKind,
			Scope:          s.Kind,
			ConfigRevision: s.ConfigRevision,
		},
		RuleModifiers:  s.RuleModifiers,
		ResolvedRules:  s.ResolvedRules,
		Snapshot:       s.ObservationSnapshot(),
		FinalizeReason: reason,
		FinalizedAt:    finalizedAt,
	})
	if err != nil {
		return err
	}
	return s.managerJobLogs.EmitAndCloseJobResultLog(ctx, payload)
}

func (s *JobScopeState) WriteDetectionLogForHit(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerKind string, hit observations.HitEntry, event jobevent.EventRecord, logger *slog.Logger) {
	if s == nil || hit.Identity.IsZero() {
		return
	}

	switch hit.Action {
	case string(rule.RuleActionTerminate):
		s.writeDetectionLog(ctx, identity, metadata, runnerKind, &hit, event, logger, "")
	case string(rule.RuleActionDetect):
		if hit.MaxAlerts <= 0 {
			s.writeDetectionLog(ctx, identity, metadata, runnerKind, &hit, event, logger, "")
			return
		}
		hitCount := s.CorrelationHitCountFor(hit.Identity)
		cap := int64(hit.MaxAlerts)
		if hitCount > cap {
			return
		}
		truncation := ""
		if hitCount == cap {
			truncation = resultdoc.AlertTruncationMaxAlertsReached
		}
		s.writeDetectionLog(ctx, identity, metadata, runnerKind, &hit, event, logger, truncation)
	case string(rule.RuleActionCollect):
		// collect is retained in observations/result summaries, not alert logs.
		return
	default:
		s.writeDetectionLog(ctx, identity, metadata, runnerKind, &hit, event, logger, "")
	}
}

func (s *JobScopeState) writeDetectionLog(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerKind string, hit *observations.HitEntry, event jobevent.EventRecord, logger *slog.Logger, truncation string) {
	if s == nil || hit == nil {
		return
	}
	if hit.Action != string(rule.RuleActionDetect) && hit.Action != string(rule.RuleActionTerminate) {
		return
	}

	ruleName, ruleDescription, rulesetRevision := s.resolvedRuleInfo(hit.Identity)
	payload, err := joblogs.MarshalDetectionLogEntry(joblogs.DetectionLogInput{
		ScopeLogContext: joblogs.ScopeLogContext{
			Identity:       identity,
			Metadata:       metadata,
			RunnerKind:     runnerKind,
			Scope:          s.Kind,
			ConfigRevision: s.ConfigRevision,
		},
		Hit:                 hit,
		Event:               event,
		RuleName:            ruleName,
		RuleDescription:     ruleDescription,
		RulesetRevision:     rulesetRevision,
		RuleAlertTruncation: truncation,
	})
	if err != nil {
		if logger != nil {
			logger.WarnContext(ctx, "detection_log_marshal_failed",
				"ruleset_id", hit.Identity.RulesetID,
				"rule_id", hit.Identity.RuleID,
				"error", err,
			)
		}
		return
	}
	if err := s.managerJobLogs.WriteDetectionPayload(ctx, payload); err != nil && logger != nil {
		logger.WarnContext(ctx, "detection_log_write_failed",
			"ruleset_id", hit.Identity.RulesetID,
			"rule_id", hit.Identity.RuleID,
			"dropped_records", s.managerJobLogs.DroppedLogRecords(managerv1.LogKind_LOG_KIND_JOB_DETECTION),
			"error", err,
		)
	}
}

func (s *JobScopeState) WriteRuntimeTelemetryLog(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerKind string, event jobevent.EventRecord, logger *slog.Logger) {
	if s == nil {
		return
	}

	payload, err := joblogs.MarshalRuntimeTelemetryLogEntry(joblogs.RuntimeTelemetryLogInput{
		ScopeLogContext: joblogs.ScopeLogContext{
			Identity:       identity,
			Metadata:       metadata,
			RunnerKind:     runnerKind,
			Scope:          s.Kind,
			ConfigRevision: s.ConfigRevision,
		},
		Event: event,
	})
	if err != nil {
		if logger != nil {
			logger.WarnContext(ctx, "runtime_telemetry_marshal_failed",
				"scope", string(s.Kind),
				"error", err,
			)
		}
		return
	}
	if err := s.managerJobLogs.WriteRuntimeTelemetryPayload(ctx, payload); err != nil && logger != nil {
		logger.WarnContext(ctx, "runtime_telemetry_write_failed",
			"scope", string(s.Kind),
			"dropped_records", s.managerJobLogs.DroppedLogRecords(managerv1.LogKind_LOG_KIND_JOB_RUNTIME_TELEMETRY),
			"error", err,
		)
	}
}

func (s *JobScopeState) FinalizeStreamingLogs(ctx context.Context) error {
	return s.managerJobLogs.FinalizeStreamingLogs(ctx)
}
