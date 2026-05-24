package rule

import (
	"fmt"
	"slices"
	"strings"
)

// MergeInput collects all sets and modifiers to be merged into ResolvedRules.
type MergeInput struct {
	RuleSets                []RuleSet
	RuleModifiers           []RuleModifier
	DefaultMaxAlertsPerRule int
	ProviderHost            string
	ProjectPath             string
}

// Merge flattens sets, applies modifiers, and produces ResolvedRules.
func Merge(in MergeInput) ResolvedRules {
	rules, warnings := flattenRules(in.RuleSets)
	validModifiers, modifierWarnings := filterValidModifiers(in.RuleModifiers)
	warnings = append(warnings, modifierWarnings...)
	rules = applyModifiers(rules, validModifiers)
	rules = applyTargetFilter(rules, in.ProviderHost, in.ProjectPath)
	rules, maxAlertWarnings := applyMaxAlertsDefaultsAndCeiling(rules, in.DefaultMaxAlertsPerRule)
	warnings = append(warnings, maxAlertWarnings...)
	return ResolvedRules{
		Rules:    rules,
		Warnings: warnings,
	}
}

func flattenRules(sets []RuleSet) ([]ResolvedRule, []MergeWarning) {
	type seen struct {
		rule      Rule
		lists     PredefinedLists
		rulesetID string
	}

	index := map[CanonicalRuleID]seen{}
	var out []ResolvedRule
	var warnings []MergeWarning

	for _, s := range sets {
		predefinedLists := NormalizePredefinedLists(s.Lists)
		for _, r := range s.Rules {
			identity := RuleIdentity{RulesetID: s.RulesetID, RuleID: r.RuleID}
			canonicalRuleID := identity.CanonicalRuleID()
			if prev, duplicate := index[canonicalRuleID]; duplicate {
				if isRuleContentEqual(prev.rule, r) && isPredefinedListsEqual(prev.lists, predefinedLists) {
					continue
				}
				warnings = append(warnings, MergeWarning{
					Kind:     "duplicate_identity_diff_content",
					Identity: identity,
				})
				// Keep runtime rule keys unique; the first loaded entry
				// remains authoritative.
				continue
			}
			out = append(out, ResolvedRule{
				CanonicalRuleID: canonicalRuleID,
				Rule:            r,
				RulesetID:       s.RulesetID,
				RulesetRevision: s.Revision,
				PredefinedLists: predefinedLists,
			})
			index[canonicalRuleID] = seen{
				rule:      r,
				lists:     predefinedLists,
				rulesetID: s.RulesetID,
			}
		}
	}

	return out, warnings
}

func filterValidModifiers(mods []RuleModifier) ([]RuleModifier, []MergeWarning) {
	valid := make([]RuleModifier, 0, len(mods))
	var warnings []MergeWarning
	for _, modifier := range mods {
		if err := ValidateRuleModifier(&modifier); err != nil {
			warnings = append(warnings, MergeWarning{
				Kind:       "invalid_modifier_skipped",
				EntryLabel: modifier.ModifierID,
				Reason:     err.Error(),
			})
			continue
		}
		valid = append(valid, modifier)
	}
	return valid, warnings
}

func applyModifiers(rules []ResolvedRule, mods []RuleModifier) []ResolvedRule {
	out := make([]ResolvedRule, 0, len(rules))
	for _, resolvedRule := range rules {
		disabled := resolvedRule.Rule.Action == ""

		for _, modifier := range mods {
			if !matchesRule(resolvedRule, modifier.Targets) {
				continue
			}
			if modifier.Disable != nil && *modifier.Disable {
				disabled = true
				resolvedRule.AppliedModifiers = append(resolvedRule.AppliedModifiers, modifier.ModifierID)
				continue
			}
			// Validation already rejects override_action: "". Keep merge
			// defensive so a bypassed invalid bundle does not silently disable
			// the rule or overwrite its action with an empty value.
			if modifier.OverrideAction != nil && *modifier.OverrideAction != "" {
				resolvedRule.Rule.Action = *modifier.OverrideAction
				disabled = false
			}
			if modifier.OverrideMaxAlerts != nil {
				resolvedRule.Rule.MaxAlerts = *modifier.OverrideMaxAlerts
			}
			if strings.TrimSpace(modifier.AddExceptions) != "" {
				resolvedRule.ExceptionClauses = append(resolvedRule.ExceptionClauses, ResolvedExceptionClause{
					Source:           strings.TrimSpace(modifier.AddExceptions),
					ModifierIdentity: modifier.ModifierID,
				})
			}
			if len(modifier.AddTargetExclude) > 0 {
				resolvedRule.Rule.Target.Exclude = append(resolvedRule.Rule.Target.Exclude, modifier.AddTargetExclude...)
			}
			resolvedRule.AppliedModifiers = append(resolvedRule.AppliedModifiers, modifier.ModifierID)
		}

		if !disabled {
			out = append(out, resolvedRule)
		}
	}
	return out
}

func applyTargetFilter(rules []ResolvedRule, providerHost, project string) []ResolvedRule {
	out := make([]ResolvedRule, 0, len(rules))
	for _, resolvedRule := range rules {
		target := resolvedRule.Rule.Target
		includeAllows := len(target.Include) == 0
		for _, matcher := range target.Include {
			if targetMatcherMatches(matcher, providerHost, project) {
				includeAllows = true
				break
			}
		}

		excludeMatches := false
		for _, matcher := range target.Exclude {
			if targetMatcherMatches(matcher, providerHost, project) {
				excludeMatches = true
				break
			}
		}

		// include is the allow gate; exclude wins when both sides match.
		if !includeAllows || excludeMatches {
			continue
		}
		out = append(out, resolvedRule)
	}
	return out
}

func targetMatcherMatches(matcher RuleTargetMatcher, providerHost, projectPath string) bool {
	return (matcher.ProviderHost == "" || matcher.ProviderHost == providerHost) &&
		(matcher.Path == "" || strings.HasPrefix(projectPath, matcher.Path))
}

// applyMaxAlertsDefaultsAndCeiling bakes the final max_alerts cap into each
// rule. Rule-local max_alerts wins, then the host/project configured default,
// then the system fallback. Out-of-range values should be rejected before merge,
// but this stays defensive and falls back with a warning instead of dropping
// the rule.
//
// The function builds a fresh out slice so the caller's input is left
// untouched. Merge is called once per host/project start, so the extra
// allocation is not on a hot path.
func applyMaxAlertsDefaultsAndCeiling(rules []ResolvedRule, configuredDefault int) ([]ResolvedRule, []MergeWarning) {
	out := make([]ResolvedRule, 0, len(rules))
	var warnings []MergeWarning
	for _, r := range rules {
		final, fellBack := ResolveMaxAlertsCap(r.Rule.MaxAlerts, configuredDefault)
		r.Rule.MaxAlerts = final
		out = append(out, r)
		if !fellBack {
			continue
		}
		warnings = append(warnings, MergeWarning{
			Kind:     "max_alerts_out_of_range",
			Identity: r.Identity(),
			Reason: fmt.Sprintf(
				"max_alerts out of [0,%d], fell back to default %d",
				MaxAlertsHardCeiling,
				DefaultMaxAlertsPerRule,
			),
		})
	}
	return out, warnings
}

func matchesRule(r ResolvedRule, targets []RuleModifierTarget) bool {
	for _, t := range targets {
		// Validation rejects empty ruleset_id, but stay defensive if a
		// malformed bundle bypasses validation.
		if t.RulesetID == "" {
			continue
		}
		if t.RulesetID != r.RulesetID {
			continue
		}
		if t.RuleID != "" && t.RuleID != r.Rule.RuleID {
			continue
		}
		return true
	}
	return false
}

func isRuleContentEqual(left, right Rule) bool {
	if left.RuleID != right.RuleID ||
		left.RuleName != right.RuleName ||
		left.Description != right.Description ||
		left.Type != right.Type ||
		left.EventType != right.EventType ||
		left.Condition != right.Condition ||
		left.Exceptions != right.Exceptions ||
		left.MaxAlerts != right.MaxAlerts ||
		left.Action != right.Action {
		return false
	}
	if !isStringMapEqual(left.Tags, right.Tags) {
		return false
	}
	if !isRuleTargetEqual(left.Target, right.Target) {
		return false
	}
	return true
}

func isRuleTargetEqual(left, right RuleTarget) bool {
	if len(left.Include) != len(right.Include) {
		return false
	}
	for i, matcher := range left.Include {
		if matcher.ProviderHost != right.Include[i].ProviderHost || matcher.Path != right.Include[i].Path {
			return false
		}
	}
	if len(left.Exclude) != len(right.Exclude) {
		return false
	}
	for i, matcher := range left.Exclude {
		if matcher.ProviderHost != right.Exclude[i].ProviderHost || matcher.Path != right.Exclude[i].Path {
			return false
		}
	}
	return true
}

func isPredefinedListsEqual(left, right PredefinedLists) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValues := range left {
		rightValues, ok := right[key]
		if !ok {
			return false
		}
		if !slices.Equal(leftValues, rightValues) {
			return false
		}
	}
	return true
}

func isStringMapEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValue := range left {
		rightValue, ok := right[key]
		if !ok || leftValue != rightValue {
			return false
		}
	}
	return true
}
