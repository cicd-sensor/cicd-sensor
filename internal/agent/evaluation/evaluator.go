package evaluation

import (
	"context"
	"log/slog"
	"os"
	"syscall"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
)

// EvaluateEvent evaluates one event and reflects the result into both scopes.
//
// activation is owned by the caller (one worker goroutine per Job, see
// Job.runEventWorker) and reused across events; we just Reset it here.
// This makes the single-goroutine assumption explicit at the boundary
// instead of hiding it inside a sync.Pool.
func EvaluateEvent(
	ctx context.Context,
	eval *EvaluationState,
	event jobevent.EventRecord,
	identity jobcontext.JobIdentity,
	metadata jobcontext.JobMetadata,
	runnerType string,
	host *jobscope.JobScopeState,
	project *jobscope.JobScopeState,
	logger *slog.Logger,
	activation *celengine.EventActivation,
) {
	if eval == nil {
		return
	}
	if event.ID == "" {
		event.ID = newEventID()
	}

	activation.Reset(celInputEventFromRecord(event))
	anyHit := false

	for _, compiled := range eval.RulesByType[event.EventType] {
		if compiled.CompiledCondition == nil {
			continue
		}

		// Event values are shared per event, but `list` is rule/ruleset-local.
		activation.SetParent(compiled.StaticActivation)
		matched, err := compiled.CompiledCondition.EvalActivation(activation)
		if err != nil {
			if logger != nil {
				logger.WarnContext(ctx, "rule_evaluation_failed",
					"canonical_rule_id", compiled.CanonicalRuleID,
					"error", err,
				)
			}
			continue
		}
		if !matched {
			continue
		}

		excluded := false
		for _, compiledException := range compiled.Exceptions {
			if compiledException.Program == nil {
				continue
			}
			exceptionMatched, err := compiledException.Program.EvalActivation(activation)
			if err != nil {
				if logger != nil {
					logger.WarnContext(ctx, "rule_exception_evaluation_failed",
						"canonical_rule_id", compiled.CanonicalRuleID,
						"exception_source", compiledException.Source,
						"modifier_identity", compiledException.ModifierIdentity,
						"error", err,
					)
				}
				continue
			}
			if exceptionMatched {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		hit := observations.HitEntry{
			Identity:  compiled.Identity,
			Action:    string(compiled.Action),
			MaxAlerts: compiled.MaxAlerts,
		}
		if compiled.Action == rule.RuleActionTerminate {
			terminateProcess(ctx, event, logger)
		}

		if compiled.FeedHost && host != nil {
			recordedHit := recordHit(host, compiled.HostRulesetRevision, hit, event)
			host.WriteDetectionLogForHit(ctx, identity, metadata, runnerType, recordedHit, event, logger)
		}
		if compiled.FeedProject && project != nil {
			recordedHit := recordHit(project, compiled.ProjectRulesetRevision, hit, event)
			project.WriteDetectionLogForHit(ctx, identity, metadata, runnerType, recordedHit, event, logger)
		}
		anyHit = true
	}

	if anyHit {
		evaluateCorrelations(ctx, eval, event, identity, metadata, runnerType, host, project, logger)
	}

	if host != nil {
		host.Observations.RecordEvent(event)
		host.WriteRuntimeEventLog(ctx, identity, metadata, runnerType, event, logger)
	}
	if project != nil {
		project.Observations.RecordEvent(event)
		project.WriteRuntimeEventLog(ctx, identity, metadata, runnerType, event, logger)
	}
}

func recordHit(
	scope *jobscope.JobScopeState,
	rulesetRevision string,
	hit observations.HitEntry,
	event jobevent.EventRecord,
) observations.HitEntry {
	hit.RulesetRevision = rulesetRevision
	scope.RecordHit(hit, event)
	return hit
}

// Correlations are one-shot per scope: once their own rule has a hit, later
// events skip them. The CEL activation reads scope-local hit counts lazily.
func evaluateCorrelations(
	ctx context.Context,
	eval *EvaluationState,
	event jobevent.EventRecord,
	identity jobcontext.JobIdentity,
	metadata jobcontext.JobMetadata,
	runnerType string,
	host *jobscope.JobScopeState,
	project *jobscope.JobScopeState,
	logger *slog.Logger,
) {
	if eval == nil || len(eval.Correlations) == 0 {
		return
	}

	for _, correlation := range eval.Correlations {
		if correlation.CompiledCondition == nil {
			continue
		}

		if correlation.FeedHost && canFireCorrelation(host, correlation.Identity) {
			hostActivation := correlationActivation(host, correlation)
			matched, err := correlation.CompiledCondition.EvalActivation(hostActivation)
			if err != nil && logger != nil {
				logger.WarnContext(ctx, "correlation_evaluation_failed",
					"canonical_rule_id", correlation.CanonicalRuleID,
					"scope", "host",
					"error", err,
				)
			} else if matched {
				hit := observations.HitEntry{
					Identity:  correlation.Identity,
					Action:    string(correlation.Action),
					MaxAlerts: correlation.MaxAlerts,
				}
				if correlation.Action == rule.RuleActionTerminate {
					terminateProcess(ctx, event, logger)
				}
				recordedHit := recordHit(host, correlation.HostRulesetRevision, hit, event)
				host.WriteDetectionLogForHit(ctx, identity, metadata, runnerType, recordedHit, event, logger)
			}
		}

		if correlation.FeedProject && canFireCorrelation(project, correlation.Identity) {
			projectActivation := correlationActivation(project, correlation)
			matched, err := correlation.CompiledCondition.EvalActivation(projectActivation)
			if err != nil && logger != nil {
				logger.WarnContext(ctx, "correlation_evaluation_failed",
					"canonical_rule_id", correlation.CanonicalRuleID,
					"scope", "project",
					"error", err,
				)
			} else if matched {
				hit := observations.HitEntry{
					Identity:  correlation.Identity,
					Action:    string(correlation.Action),
					MaxAlerts: correlation.MaxAlerts,
				}
				if correlation.Action == rule.RuleActionTerminate {
					terminateProcess(ctx, event, logger)
				}
				recordedHit := recordHit(project, correlation.ProjectRulesetRevision, hit, event)
				project.WriteDetectionLogForHit(ctx, identity, metadata, runnerType, recordedHit, event, logger)
			}
		}
	}
}

func terminateProcess(ctx context.Context, event jobevent.EventRecord, logger *slog.Logger) {
	pid := event.Process.PID
	if pid <= 0 {
		logger.WarnContext(ctx, "terminate_process_skipped", "reason", "missing_pid")
		return
	}
	if pid == int32(os.Getpid()) {
		logger.WarnContext(ctx, "terminate_process_skipped", "reason", "self_pid", "pid", pid)
		return
	}
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		logger.WarnContext(ctx, "terminate_process_failed", "pid", pid, "error", err)
		return
	}
	logger.WarnContext(ctx, "terminate_process_sent", "pid", pid)
}

func newEventID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

// Correlation rules fire once per scope; their own hit count becomes the guard.
func canFireCorrelation(scope *jobscope.JobScopeState, identity rule.RuleIdentity) bool {
	return scope != nil && scope.CorrelationHitCountFor(identity) == 0
}

func correlationActivation(scope *jobscope.JobScopeState, correlation celengine.CompiledCorrelation) cel.Activation {
	if scope == nil {
		return nil
	}
	return correlation.NewActivation(scope.CorrelationHitCountFor)
}
