// Package rule defines rule schema types.
package rule

import (
	"regexp"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

type RuleAction string

const (
	RuleActionDetect    RuleAction = "detect"
	RuleActionTerminate RuleAction = "terminate"
	RuleActionCollect   RuleAction = "collect"
)

var RuleIDPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

const DefaultMaxAlertsPerRule = 10

const MaxAlertsHardCeiling = 100

// ResolveMaxAlertsCap resolves the per-rule alert cap from the rule value,
// host/project configured default, and system fallback.
func ResolveMaxAlertsCap(ruleValue, configuredDefault int) (cap int, fellBack bool) {
	if ruleValue < 0 || ruleValue > MaxAlertsHardCeiling {
		return DefaultMaxAlertsPerRule, true
	}
	if ruleValue > 0 {
		return ruleValue, false
	}
	if configuredDefault < 0 || configuredDefault > MaxAlertsHardCeiling {
		return DefaultMaxAlertsPerRule, true
	}
	if configuredDefault > 0 {
		return configuredDefault, false
	}
	return DefaultMaxAlertsPerRule, false
}

type RuleTargetMatcher struct {
	ProviderHost string `json:"provider_host,omitempty" yaml:"provider_host,omitempty"`
	Path         string `json:"path,omitempty" yaml:"path,omitempty"`
}

type RuleTarget struct {
	Include []RuleTargetMatcher `json:"include,omitempty" yaml:"include,omitempty"`
	Exclude []RuleTargetMatcher `json:"exclude,omitempty" yaml:"exclude,omitempty"`
}

func (t RuleTarget) IsZero() bool {
	return len(t.Include) == 0 && len(t.Exclude) == 0
}

type Rule struct {
	RuleID      string            `json:"rule_id" yaml:"rule_id"`
	RuleName    string            `json:"rule_name,omitempty" yaml:"rule_name,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Type        string            `json:"type,omitempty" yaml:"type,omitempty"`
	EventType   jobevent.Type     `json:"event_type,omitempty" yaml:"event_type,omitempty"`
	Target      RuleTarget        `json:"target,omitzero" yaml:"target,omitempty"`
	Condition   string            `json:"condition" yaml:"condition"`
	Exceptions  string            `json:"exceptions,omitempty" yaml:"exceptions,omitempty"`
	MaxAlerts   int               `json:"max_alerts,omitempty" yaml:"max_alerts,omitempty"`
	Action      RuleAction        `json:"action" yaml:"action"`
	Tags        map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

type RuleSet struct {
	RulesetID string              `json:"ruleset_id" yaml:"ruleset_id"`
	Revision  string              `json:"revision,omitempty" yaml:"-"`
	Lists     map[string][]string `json:"lists,omitempty" yaml:"lists,omitempty"`
	Rules     []Rule              `json:"rules" yaml:"rules"`
}

type RuleModifierTarget struct {
	RulesetID string `json:"ruleset_id" yaml:"ruleset_id"`
	RuleID    string `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
}

type RuleModifier struct {
	ModifierID        string               `json:"modifier_id" yaml:"modifier_id"`
	Revision          string               `json:"revision,omitempty" yaml:"-"`
	Description       string               `json:"description,omitempty" yaml:"description,omitempty"`
	Targets           []RuleModifierTarget `json:"targets" yaml:"targets"`
	OverrideAction    *RuleAction          `json:"override_action,omitempty" yaml:"override_action,omitempty"`
	OverrideMaxAlerts *int                 `json:"override_max_alerts,omitempty" yaml:"override_max_alerts,omitempty"`
	AddExceptions     string               `json:"add_exceptions,omitempty" yaml:"add_exceptions,omitempty"`
	AddTargetExclude  []RuleTargetMatcher  `json:"add_target_exclude,omitempty" yaml:"add_target_exclude,omitempty"`
	Disable           *bool                `json:"disable,omitempty" yaml:"disable,omitempty"`
}
