// Package evaluation compiles resolved rules and evaluates job events.
package evaluation

import (
	"sync"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
)

var (
	ruleEnvOnce sync.Once
	ruleEnv     *celengine.Env
	ruleEnvErr  error
)

// EvaluationState is the immutable compiled rule bundle used on the event hot path.
type EvaluationState struct {
	RulesByType  map[jobevent.Type][]celengine.CompiledRule
	Correlations []celengine.CompiledCorrelation
}

// NewEvaluationState merges host/project rules and compiles CEL programs.
// Compile warnings are written back to the originating ResolvedRules.
func NewEvaluationState(host, project *rule.ResolvedRules) *EvaluationState {
	dropPreviousCompileWarnings(host)
	dropPreviousCompileWarnings(project)

	entries := mergeEvaluationRules(host, project)
	out := &EvaluationState{
		RulesByType: make(map[jobevent.Type][]celengine.CompiledRule),
	}
	if len(entries) == 0 {
		return out
	}

	env, err := sharedRuleEnv()
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if entry.rule.Rule.Type == "correlation" {
			continue
		}

		condition, err := env.Compile(entry.rule.CanonicalRuleID.String(), entry.rule.Rule.EventType, entry.rule.Rule.Condition, entry.rule.PredefinedLists)
		if err != nil {
			appendCompileWarningForEntry(entry, err.Error(), host, project)
			continue
		}

		exceptions, err := compileRuleExceptions(env, entry.rule)
		if err != nil {
			appendCompileWarningForEntry(entry, err.Error(), host, project)
			continue
		}
		staticActivation, err := celengine.NewListActivation(entry.rule.PredefinedLists)
		if err != nil {
			appendCompileWarningForEntry(entry, err.Error(), host, project)
			continue
		}

		out.RulesByType[entry.rule.Rule.EventType] = append(out.RulesByType[entry.rule.Rule.EventType], celengine.CompiledRule{
			CanonicalRuleID:        entry.rule.CanonicalRuleID,
			Identity:               entry.rule.Identity(),
			HostRulesetRevision:    entry.hostRulesetRevision,
			ProjectRulesetRevision: entry.projectRulesetRevision,
			Action:                 entry.rule.Rule.Action,
			MaxAlerts:              entry.rule.Rule.MaxAlerts,
			CompiledCondition:      condition,
			Exceptions:             exceptions,
			StaticActivation:       staticActivation,
			FeedHost:               entry.feedHost,
			FeedProject:            entry.feedProject,
		})
	}

	out.Correlations = compileAndMergeEvaluationCorrelations(host, project, env)

	return out
}

// sharedRuleEnv contains only immutable CEL declarations. Job-specific rules,
// lists, activations, and observations stay outside this shared environment.
func sharedRuleEnv() (*celengine.Env, error) {
	ruleEnvOnce.Do(func() {
		ruleEnv, ruleEnvErr = celengine.NewEnv()
	})
	return ruleEnv, ruleEnvErr
}
