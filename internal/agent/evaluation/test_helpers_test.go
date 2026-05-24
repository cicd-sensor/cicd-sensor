package evaluation

import (
	"context"
	"io"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

var (
	testCtx    = context.Background()
	testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
)

// scopeResolvedRules returns a pointer into a scope's resolved rule storage,
// or nil when the scope itself is nil. Tests use it to feed a host or project
// scope's ResolvedRules into NewEvaluationState the same way job.go does in
// production.
func scopeResolvedRules(s *jobscope.JobScopeState) *rule.ResolvedRules {
	if s == nil {
		return nil
	}
	return &s.ResolvedRules
}

func boolPtr(value bool) *bool {
	return &value
}

func resolvedRules(setIdentity string, rules ...rule.Rule) rule.ResolvedRules {
	out := rule.ResolvedRules{
		Rules: make([]rule.ResolvedRule, 0, len(rules)),
	}
	for _, resolvedRule := range rules {
		identity := rule.RuleIdentity{RulesetID: setIdentity, RuleID: resolvedRule.RuleID}
		out.Rules = append(out.Rules, rule.ResolvedRule{
			CanonicalRuleID: identity.CanonicalRuleID(),
			Rule:            resolvedRule,
			RulesetID:       setIdentity,
		})
	}
	return out
}

func detectHits(snapshot observations.StateSnapshot) observations.HitSnapshot {
	return slices.DeleteFunc(slices.Clone(snapshot.Hits), func(hit observations.HitSummary) bool {
		return hit.Action != string(rule.RuleActionDetect)
	})
}

func newCorrelationScope(setIdentity string, rules []rule.Rule) *jobscope.JobScopeState {
	scope := jobscope.NewHost()
	scope.RuleSets = []rule.RuleSet{{
		RulesetID: setIdentity,
		Rules:     rules,
	}}
	scope.ResolveRules(jobcontext.JobIdentity{})
	return scope
}

func newProjectScopeWithRules(setIdentity string, rules []rule.Rule) *jobscope.JobScopeState {
	scope := jobscope.NewProject()
	scope.RuleSets = []rule.RuleSet{{
		RulesetID: setIdentity,
		Rules:     rules,
	}}
	scope.ResolveRules(jobcontext.JobIdentity{})
	return scope
}

func testDispatchEvent(execPath, host string, port int64) jobevent.EventRecord {
	return jobevent.EventRecord{
		EventType: jobevent.NetworkConnect,
		Timestamp: time.Date(2026, 4, 16, 1, 2, 3, 4, time.UTC),
		Payload: map[string]any{
			"remote_ip":   host,
			"remote_port": port,
			"protocol":    "tcp",
		},
		Process: jobevent.ProcessSummary{
			PID:      int32(os.Getpid()),
			ExecPath: execPath,
		},
		Tags: map[string]string{},
	}
}
