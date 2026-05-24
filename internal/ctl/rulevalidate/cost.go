package rulevalidate

import (
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/google/cel-go/checker"
)

// CostWarnThreshold is an advisory rule-authoring threshold. It's
// deliberately loose: a single ancestor × argv scan with literal
// substring matching scores under it; the warning is meant to flag
// rules that pile multiple such non-specialized nested scans together.
const CostWarnThreshold uint64 = 5_000

// Typical CI sizes keep cost warnings actionable. Runtime safety is separate.
// argv / ancestors counts are intentionally on the low side of what CI
// processes look like in practice so `exists` doesn't get charged for a
// worst-case fan-out that nobody encounters.
const (
	pathTypicalBytes     uint64 = 128
	ipTypicalBytes       uint64 = 45
	protocolTypicalBytes uint64 = 8
	argvTypicalItems     uint64 = 16
	argvItemTypicalBytes uint64 = 48
	ancestorTypicalItems uint64 = 8
	listTypicalItems     uint64 = 8
	listItemTypicalBytes uint64 = 48
)

// RuleCostKey identifies a costed expression within a rule set.
type RuleCostKey struct {
	Identity rule.RuleIdentity
	Kind     string // "condition" or "exception"
}

// RuleSetCosts returns advisory static CEL costs. Compile failures are reported
// by rulevalidate, so this pass skips them.
func RuleSetCosts(env *celengine.Env, set rule.RuleSet) map[RuleCostKey]uint64 {
	out := make(map[RuleCostKey]uint64)
	predefinedLists := rule.NormalizePredefinedLists(set.Lists)
	for _, candidate := range set.Rules {
		if candidate.Type == "correlation" {
			continue
		}
		identity := rule.RuleIdentity{RulesetID: set.RulesetID, RuleID: candidate.RuleID}
		canonicalRuleID := identity.CanonicalRuleID()
		if cost, ok := estimateExpressionCost(env, canonicalRuleID.String(), candidate.EventType, candidate.Condition, predefinedLists); ok {
			out[RuleCostKey{Identity: identity, Kind: "condition"}] = cost
		}
		if strings.TrimSpace(candidate.Exceptions) != "" {
			if cost, ok := estimateExpressionCost(env, canonicalRuleID.String(), candidate.EventType, candidate.Exceptions, predefinedLists); ok {
				out[RuleCostKey{Identity: identity, Kind: "exception"}] = cost
			}
		}
	}
	return out
}

func estimateExpressionCost(env *celengine.Env, ruleID string, eventType jobevent.Type, source string, predefinedLists map[string][]string) (uint64, bool) {
	if _, err := env.Compile(ruleID, eventType, source, predefinedLists); err != nil {
		return 0, false
	}
	celEnv, err := env.EnvForType(eventType)
	if err != nil {
		return 0, false
	}
	ast, iss := celEnv.Compile(source)
	if iss != nil && iss.Err() != nil {
		return 0, false
	}
	if ast == nil {
		return 0, false
	}
	cost, err := checker.Cost(ast.NativeRep(), variableSizeEstimator{})
	if err != nil {
		return 0, false
	}
	return cost.Max, true
}

// variableSizeEstimator supplies typical sizes; cel-go owns the cost formulas.
type variableSizeEstimator struct{}

func (variableSizeEstimator) EstimateSize(node checker.AstNode) *checker.SizeEstimate {
	p := node.Path()
	if len(p) == 0 {
		return nil
	}
	switch p[0] {
	case "path":
		return &checker.SizeEstimate{Min: 0, Max: pathTypicalBytes}
	case "remote_ip":
		return &checker.SizeEstimate{Min: 0, Max: ipTypicalBytes}
	case "protocol":
		return &checker.SizeEstimate{Min: 0, Max: protocolTypicalBytes}
	case "process":
		if len(p) < 2 {
			return nil
		}
		switch p[1] {
		case "exec_path":
			return &checker.SizeEstimate{Min: 0, Max: pathTypicalBytes}
		case "argv":
			if len(p) >= 3 && p[2] == "@items" {
				return &checker.SizeEstimate{Min: 0, Max: argvItemTypicalBytes}
			}
			return &checker.SizeEstimate{Min: 0, Max: argvTypicalItems}
		case "ancestors":
			if len(p) < 3 || p[2] != "@items" {
				return &checker.SizeEstimate{Min: 0, Max: ancestorTypicalItems}
			}
			if len(p) < 4 {
				return nil
			}
			switch p[3] {
			case "exec_path":
				return &checker.SizeEstimate{Min: 0, Max: pathTypicalBytes}
			case "argv":
				if len(p) >= 5 && p[4] == "@items" {
					return &checker.SizeEstimate{Min: 0, Max: argvItemTypicalBytes}
				}
				return &checker.SizeEstimate{Min: 0, Max: argvTypicalItems}
			}
		}
		return nil
	case "list":
		if len(p) >= 3 && p[2] == "@items" {
			return &checker.SizeEstimate{Min: 0, Max: listItemTypicalBytes}
		}
		return &checker.SizeEstimate{Min: 0, Max: listTypicalItems}
	}
	return nil
}

func (variableSizeEstimator) EstimateCallCost(string, string, *checker.AstNode, []checker.AstNode) *checker.CallEstimate {
	return nil
}
