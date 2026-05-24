package evaluation

import (
	"fmt"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
)

func compileRuleExceptions(env *celengine.Env, resolved rule.ResolvedRule) ([]celengine.CompiledException, error) {
	var out []celengine.CompiledException

	// resolved is scope-local after rule.Merge. Shared host/project entries
	// reach here only when their exception clauses are content-equivalent.
	if strings.TrimSpace(resolved.Rule.Exceptions) != "" {
		prog, err := env.Compile(resolved.CanonicalRuleID.String(), resolved.Rule.EventType, resolved.Rule.Exceptions, resolved.PredefinedLists)
		if err != nil {
			return nil, fmt.Errorf("compile base exception %q: %w", resolved.Rule.Exceptions, err)
		}
		out = append(out, celengine.CompiledException{
			Program: prog,
			Source:  resolved.Rule.Exceptions,
		})
	}

	for _, clause := range resolved.ExceptionClauses {
		prog, err := env.Compile(resolved.CanonicalRuleID.String(), resolved.Rule.EventType, clause.Source, resolved.PredefinedLists)
		if err != nil {
			if clause.ModifierIdentity != "" {
				return nil, fmt.Errorf("compile exception clause from modifier %q %q: %w", clause.ModifierIdentity, clause.Source, err)
			}
			return nil, fmt.Errorf("compile exception clause %q: %w", clause.Source, err)
		}
		out = append(out, celengine.CompiledException{
			Program:          prog,
			Source:           clause.Source,
			ModifierIdentity: clause.ModifierIdentity,
		})
	}

	return out, nil
}

func compileAndMergeEvaluationCorrelations(host, project *rule.ResolvedRules, env *celengine.Env) []celengine.CompiledCorrelation {
	type compiledCorrelationEntry struct {
		correlation celengine.CompiledCorrelation
		source      rule.ResolvedRule
	}

	// Correlations compile per scope because rule refs resolve against that
	// scope's enabled rules, then equivalent host/project correlations share CEL.
	// Scope-local duplicates are resolved by rule.Merge. This tracks the first
	// out index for each canonical ID so equivalent correlations share CEL.
	sharedEvalIndexByCanonical := make(map[rule.CanonicalRuleID]int)
	out := make([]compiledCorrelationEntry, 0)

	add := func(scopeName string, scope *rule.ResolvedRules) {
		if scope == nil {
			return
		}

		availableRuleCanonicals := availableRuleCanonicalsBySet(scope.Rules)
		for _, resolvedRule := range scope.Rules {
			if resolvedRule.Rule.Type != "correlation" {
				continue
			}

			availableRuleCanonicalsForSet, found := availableRuleCanonicals[resolvedRule.RulesetID]
			if !found {
				appendCompileWarning(scope, resolvedRule, fmt.Sprintf("enabled rules for set %q not found", resolvedRule.RulesetID))
				continue
			}

			compiled, err := env.CompileCorrelation(resolvedRule.RulesetID, resolvedRule.Rule, availableRuleCanonicalsForSet)
			if err != nil {
				appendCompileWarning(scope, resolvedRule, err.Error())
				continue
			}

			if idx, hasSharedEval := sharedEvalIndexByCanonical[compiled.CanonicalRuleID]; hasSharedEval {
				if rule.IsResolvedRuleContentEqual(out[idx].source, resolvedRule) {
					markCorrelationForScope(&out[idx].correlation, scopeName, resolvedRule.RulesetRevision)
					continue
				}
			} else {
				sharedEvalIndexByCanonical[compiled.CanonicalRuleID] = len(out)
			}

			markCorrelationForScope(compiled, scopeName, resolvedRule.RulesetRevision)
			compiled.MaxAlerts = resolvedRule.Rule.MaxAlerts
			out = append(out, compiledCorrelationEntry{
				correlation: *compiled,
				source:      resolvedRule,
			})
		}
	}

	add(scopeHost, host)
	add(scopeProject, project)

	compiled := make([]celengine.CompiledCorrelation, 0, len(out))
	for _, entry := range out {
		compiled = append(compiled, entry.correlation)
	}
	return compiled
}

func markCorrelationForScope(compiled *celengine.CompiledCorrelation, scope, revision string) {
	switch scope {
	case scopeHost:
		compiled.FeedHost = true
		compiled.HostRulesetRevision = revision
	case scopeProject:
		compiled.FeedProject = true
		compiled.ProjectRulesetRevision = revision
	}
}

func availableRuleCanonicalsBySet(resolvedRules []rule.ResolvedRule) map[string]map[string]rule.CanonicalRuleID {
	available := make(map[string]map[string]rule.CanonicalRuleID)
	for _, resolvedRule := range resolvedRules {
		if resolvedRule.Rule.Type == "correlation" {
			continue
		}
		rulesForSet, found := available[resolvedRule.RulesetID]
		if !found {
			rulesForSet = make(map[string]rule.CanonicalRuleID)
			available[resolvedRule.RulesetID] = rulesForSet
		}
		rulesForSet[resolvedRule.Rule.RuleID] = resolvedRule.CanonicalRuleID
	}
	return available
}

func dropPreviousCompileWarnings(rr *rule.ResolvedRules) {
	if rr == nil {
		return
	}

	// Rebuilds reuse scope state, so preserve merge warnings and refresh only
	// compile warnings.
	filtered := rr.Warnings[:0]
	for _, warning := range rr.Warnings {
		if warning.Kind == "compile_error" {
			continue
		}
		filtered = append(filtered, warning)
	}
	rr.Warnings = filtered
}

func appendCompileWarningForEntry(entry compiledRuleEntry, reason string, host, project *rule.ResolvedRules) {
	if entry.feedHost {
		appendCompileWarning(host, entry.rule, reason)
	}
	if entry.feedProject {
		appendCompileWarning(project, entry.rule, reason)
	}
}

func appendCompileWarning(rr *rule.ResolvedRules, resolvedRule rule.ResolvedRule, reason string) {
	if rr == nil {
		return
	}

	rr.Warnings = append(rr.Warnings, rule.MergeWarning{
		Kind:     "compile_error",
		Identity: resolvedRule.Identity(),
		Reason:   reason,
	})
}
