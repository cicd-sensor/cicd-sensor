package rulevalidate

import (
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
)

type CompileError struct {
	Identity rule.RuleIdentity
	Reason   string
	Source   string
}

func CompileSet(env *celengine.Env, set rule.RuleSet) []CompileError {
	predefinedLists := rule.NormalizePredefinedLists(set.Lists)
	if _, err := celengine.NewListActivation(predefinedLists); err != nil {
		return []CompileError{{
			Identity: rule.RuleIdentity{RulesetID: set.RulesetID},
			Reason:   err.Error(),
		}}
	}

	availableRuleCanonicals := make(map[string]rule.CanonicalRuleID)
	for _, candidate := range set.Rules {
		if candidate.Type == "correlation" {
			continue
		}
		identity := rule.RuleIdentity{RulesetID: set.RulesetID, RuleID: candidate.RuleID}
		availableRuleCanonicals[candidate.RuleID] = identity.CanonicalRuleID()
	}

	var compileErrors []CompileError
	for _, candidate := range set.Rules {
		identity := rule.RuleIdentity{RulesetID: set.RulesetID, RuleID: candidate.RuleID}
		canonicalRuleID := identity.CanonicalRuleID()
		if candidate.Type == "correlation" {
			if _, err := env.CompileCorrelation(set.RulesetID, candidate, availableRuleCanonicals); err != nil {
				compileErrors = append(compileErrors, CompileError{
					Identity: identity,
					Reason:   err.Error(),
					Source:   candidate.Condition,
				})
			}
			continue
		}

		if _, err := env.Compile(canonicalRuleID.String(), candidate.EventType, candidate.Condition, predefinedLists); err != nil {
			compileErrors = append(compileErrors, CompileError{
				Identity: identity,
				Reason:   err.Error(),
				Source:   candidate.Condition,
			})
			continue
		}

		if strings.TrimSpace(candidate.Exceptions) == "" {
			continue
		}
		if _, err := env.Compile(canonicalRuleID.String(), candidate.EventType, candidate.Exceptions, predefinedLists); err != nil {
			compileErrors = append(compileErrors, CompileError{
				Identity: identity,
				Reason:   err.Error(),
				Source:   candidate.Exceptions,
			})
		}
	}

	return compileErrors
}
