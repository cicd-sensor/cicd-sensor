package evaluation

import (
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

const (
	scopeHost    = string(jobcontext.ScopeTypeHost)
	scopeProject = string(jobcontext.ScopeTypeProject)
)

type compiledRuleEntry struct {
	rule        rule.ResolvedRule
	feedHost    bool
	feedProject bool
	// Equivalent host/project rules share one compiled program, but logs must
	// keep the ruleset revision of the scope that receives the hit.
	hostRulesetRevision    string
	projectRulesetRevision string
}

func mergeEvaluationRules(host, project *rule.ResolvedRules) []compiledRuleEntry {
	var hostRules []rule.ResolvedRule
	if host != nil {
		hostRules = host.Rules
	}
	var projectRules []rule.ResolvedRule
	if project != nil {
		projectRules = project.Rules
	}

	// Scope-local duplicates are resolved by rule.Merge. This tracks the first
	// out index for each canonical ID so equivalent host/project rules share CEL.
	sharedEvalIndexByCanonical := make(map[rule.CanonicalRuleID]int)
	out := make([]compiledRuleEntry, 0, len(hostRules)+len(projectRules))

	add := func(scope string, resolvedRules []rule.ResolvedRule) {
		for _, resolvedRule := range resolvedRules {
			if idx, hasSharedEval := sharedEvalIndexByCanonical[resolvedRule.CanonicalRuleID]; hasSharedEval {
				if rule.IsResolvedRuleContentEqual(out[idx].rule, resolvedRule) {
					markEntryForScope(&out[idx], scope, resolvedRule.RulesetRevision)
					continue
				}
			} else {
				sharedEvalIndexByCanonical[resolvedRule.CanonicalRuleID] = len(out)
			}

			entry := compiledRuleEntry{rule: resolvedRule}
			markEntryForScope(&entry, scope, resolvedRule.RulesetRevision)
			out = append(out, entry)
		}
	}

	add(scopeHost, hostRules)
	add(scopeProject, projectRules)
	return out
}

func markEntryForScope(entry *compiledRuleEntry, scope, revision string) {
	switch scope {
	case scopeHost:
		entry.feedHost = true
		entry.hostRulesetRevision = revision
	case scopeProject:
		entry.feedProject = true
		entry.projectRulesetRevision = revision
	}
}
