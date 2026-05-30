// Package rule holds rule types, validation, and resolution logic.
package rule

import (
	"slices"
)

// ResolvedRule is a scope-local rule after resolution. Rule.RuleID remains the
// author-facing local ID; CanonicalRuleID is the runtime key
// "<ruleset_id>/<rule_id>" used by evaluation and summaries.
type ResolvedRule struct {
	CanonicalRuleID  CanonicalRuleID           `json:"canonical_rule_id"`
	Rule             Rule                      `json:"rule"`
	RulesetID        string                    `json:"ruleset_id"`
	RulesetRevision  string                    `json:"ruleset_revision,omitempty"`
	AppliedModifiers []string                  `json:"applied_modifiers,omitempty"`
	ExceptionClauses []ResolvedExceptionClause `json:"exception_clauses,omitempty"`
	PredefinedLists  PredefinedLists           `json:"lists,omitempty"`
}

func (r ResolvedRule) Identity() RuleIdentity {
	return RuleIdentity{RulesetID: r.RulesetID, RuleID: r.Rule.RuleID}
}

// ResolvedExceptionClause is one additional exception clause attached during
// rule resolution from a modifier's add_exceptions field.
type ResolvedExceptionClause struct {
	Source           string `json:"source"`
	ModifierIdentity string `json:"modifier_identity,omitempty"`
}

// ResolveWarning records a collision or skip during rule resolution.
type ResolveWarning struct {
	Kind       string       `json:"kind"`
	Identity   RuleIdentity `json:"identity,omitempty"`
	EntryLabel string       `json:"entry_label,omitempty"`
	Reason     string       `json:"reason,omitempty"`
}

// ResolvedRules is the agent-side output of resolving all sets and modifiers.
// The manager never produces it.
type ResolvedRules struct {
	Rules    []ResolvedRule   `json:"rules"`
	Warnings []ResolveWarning `json:"warnings,omitempty"`
}

func (r ResolvedRules) Lookup(identity RuleIdentity) (ResolvedRule, bool) {
	for _, resolved := range r.Rules {
		if resolved.Identity() == identity {
			return resolved, true
		}
	}
	return ResolvedRule{}, false
}

// IsResolvedRuleContentEqual compares the rule content, ignoring identity.
func IsResolvedRuleContentEqual(left, right ResolvedRule) bool {
	if !isRuleContentEqual(left.Rule, right.Rule) {
		return false
	}
	if !slices.Equal(left.AppliedModifiers, right.AppliedModifiers) {
		return false
	}
	if !isResolvedExceptionClausesEqual(left.ExceptionClauses, right.ExceptionClauses) {
		return false
	}
	return isPredefinedListsEqual(left.PredefinedLists, right.PredefinedLists)
}

func isResolvedExceptionClausesEqual(left, right []ResolvedExceptionClause) bool {
	return slices.EqualFunc(left, right, func(a, b ResolvedExceptionClause) bool {
		return a.Source == b.Source && a.ModifierIdentity == b.ModifierIdentity
	})
}
