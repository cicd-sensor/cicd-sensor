package jobscope

import (
	"context"
	"errors"
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

type SummaryLogInputs struct {
	Identity   jobcontext.JobIdentity
	Metadata   jobcontext.JobMetadata
	RunnerType string
	StartedAt  time.Time
}

func (s *JobScopeState) EmitSummaryLog(ctx context.Context, in SummaryLogInputs, reason string, finalizedAt time.Time) error {
	if s == nil || !s.managerJobLogs.HasSummaryLog() {
		return nil
	}
	payload, err := joblogs.MarshalSummaryLogEntry(joblogs.SummaryLogInput{
		ScopeLogContext: joblogs.ScopeLogContext{
			Identity:       in.Identity,
			Metadata:       in.Metadata,
			RunnerType:     in.RunnerType,
			Scope:          s.Type,
			ConfigRevision: s.ConfigRevision,
		},
		RuleModifiers:  s.RuleModifiers,
		ResolvedRules:  s.ResolvedRules,
		Snapshot:       s.ObservationSnapshot(),
		FinalizeReason: reason,
		StartedAt:      in.StartedAt,
		FinalizedAt:    finalizedAt,
	})
	if err != nil {
		return err
	}
	return s.managerJobLogs.EmitAndCloseSummaryLog(ctx, payload)
}

func (s *JobScopeState) WriteDetectionLogForHit(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerType string, hit observations.HitEntry, event jobevent.EventRecord, logger *slog.Logger) {
	if s == nil || hit.Identity.IsZero() {
		return
	}

	switch hit.Action {
	case string(rule.RuleActionTerminate):
		s.writeDetectionLog(ctx, identity, metadata, runnerType, &hit, event, logger, "")
	case string(rule.RuleActionDetect), string(rule.RuleActionCollect):
		if hit.MaxAlerts <= 0 {
			s.writeDetectionLog(ctx, identity, metadata, runnerType, &hit, event, logger, "")
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
		s.writeDetectionLog(ctx, identity, metadata, runnerType, &hit, event, logger, truncation)
	}
}

func (s *JobScopeState) writeDetectionLog(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerType string, hit *observations.HitEntry, event jobevent.EventRecord, logger *slog.Logger, truncation string) {
	if s == nil || hit == nil {
		return
	}

	ruleName, ruleDescription, rulesetRevision := s.resolvedRuleInfo(hit.Identity)
	payload, err := joblogs.MarshalDetectionLogEntry(joblogs.DetectionLogInput{
		ScopeLogContext: joblogs.ScopeLogContext{
			Identity:   identity,
			Metadata:   metadata,
			RunnerType: runnerType,
			Scope:      s.Type,
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
			"dropped_records", s.managerJobLogs.DroppedLogRecords(managerv1.LogType_LOG_TYPE_DETECTION),
			"error", err,
		)
	}
}

func (s *JobScopeState) WriteRuntimeEventLog(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerType string, event jobevent.EventRecord, logger *slog.Logger) {
	if s == nil {
		return
	}

	payload, err := joblogs.MarshalRuntimeEventLogEntry(joblogs.RuntimeEventLogInput{
		ScopeLogContext: joblogs.ScopeLogContext{
			Identity:   identity,
			Metadata:   metadata,
			RunnerType: runnerType,
			Scope:      s.Type,
		},
		Event: event,
	})
	if err != nil {
		if logger != nil {
			logger.WarnContext(ctx, "runtime_event_marshal_failed",
				"scope", string(s.Type),
				"error", err,
			)
		}
		return
	}
	if err := s.managerJobLogs.WriteRuntimeEventPayload(ctx, payload); err != nil && logger != nil {
		logger.WarnContext(ctx, "runtime_event_write_failed",
			"scope", string(s.Type),
			"dropped_records", s.managerJobLogs.DroppedLogRecords(managerv1.LogType_LOG_TYPE_RUNTIME_EVENT),
			"error", err,
		)
	}
	if s.debugOutput != nil {
		_ = s.debugOutput.WriteRuntimeEventPayload(ctx, payload)
	}
}

func (s *JobScopeState) FinalizeStreamingLogs(ctx context.Context) error {
	return errors.Join(
		s.managerJobLogs.FinalizeStreamingLogs(ctx),
		// Project result normally closes debug output before the action reads it.
		// This covers shutdown, TTL, and other finalize paths that never request
		// a project result.
		s.CloseDebugOutput(ctx),
	)
}

func (s *JobScopeState) CloseDebugOutput(ctx context.Context) error {
	if s == nil || s.debugOutput == nil {
		return nil
	}
	return s.debugOutput.Close(ctx)
}
