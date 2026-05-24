package rule

import (
	"errors"
	"fmt"
	"strings"
)

func ValidateRuleSet(s *RuleSet) error {
	var errs []error
	if s.RulesetID == "" {
		errs = append(errs, errors.New("ruleset_id is required"))
	}

	seen := make(map[string]int, len(s.Rules))
	for i, r := range s.Rules {
		if r.RuleID == "" {
			errs = append(errs, fmt.Errorf("rules[%d]: rule_id is required", i))
		} else if !RuleIDPattern.MatchString(r.RuleID) {
			errs = append(errs, fmt.Errorf(
				"rules[%d]: rule_id %q must match %s (letters / digits / underscore, not starting with digit)",
				i, r.RuleID, RuleIDPattern,
			))
		} else if prev, ok := seen[r.RuleID]; ok {
			errs = append(errs, fmt.Errorf("rules[%d]: duplicate rule_id %q (first at rules[%d])", i, r.RuleID, prev))
		} else {
			seen[r.RuleID] = i
		}
		if strings.TrimSpace(r.Condition) == "" {
			errs = append(errs, fmt.Errorf("rules[%d]: condition is required", i))
		}
		if r.Type != "correlation" && r.EventType == "" {
			errs = append(errs, fmt.Errorf("rules[%d]: event_type is required", i))
		}
		if r.Action == "" {
			errs = append(errs, fmt.Errorf("rules[%d]: action is required", i))
		} else {
			switch r.Action {
			case RuleActionDetect, RuleActionTerminate, RuleActionCollect:
			default:
				errs = append(errs, fmt.Errorf("rules[%d]: action must be detect, terminate, or collect", i))
			}
		}
		if r.MaxAlerts < 0 {
			errs = append(errs, fmt.Errorf("rules[%d]: max_alerts must be non-negative", i))
		}
		errs = append(errs, validateRuleTarget(r.Target, fmt.Sprintf("rules[%d].target", i))...)
	}

	return errors.Join(errs...)
}

func validateRuleTarget(target RuleTarget, field string) []error {
	var errs []error

	if target.Include != nil && len(target.Include) == 0 {
		errs = append(errs, fmt.Errorf("%s.include must not be an empty list", field))
	}
	for i, matcher := range target.Include {
		if strings.TrimSpace(matcher.ProviderHost) == "" && strings.TrimSpace(matcher.Path) == "" {
			errs = append(errs, fmt.Errorf("%s.include[%d] must set provider_host or path", field, i))
		}
	}

	if target.Exclude != nil && len(target.Exclude) == 0 {
		errs = append(errs, fmt.Errorf("%s.exclude must not be an empty list", field))
	}
	for i, matcher := range target.Exclude {
		if strings.TrimSpace(matcher.ProviderHost) == "" && strings.TrimSpace(matcher.Path) == "" {
			errs = append(errs, fmt.Errorf("%s.exclude[%d] must set provider_host or path", field, i))
		}
	}

	return errs
}

func ValidateRuleModifier(m *RuleModifier) error {
	var errs []error
	if m.ModifierID == "" {
		errs = append(errs, errors.New("modifier_id is required"))
	}
	if len(m.Targets) == 0 {
		errs = append(errs, errors.New("at least one target is required"))
	}
	for i, t := range m.Targets {
		if t.RulesetID == "" {
			errs = append(errs, fmt.Errorf("targets[%d]: ruleset_id is required", i))
		}
	}
	if m.OverrideAction != nil && *m.OverrideAction == "" {
		errs = append(errs, errors.New("override_action must not be empty"))
	} else if m.OverrideAction != nil {
		switch *m.OverrideAction {
		case RuleActionDetect, RuleActionTerminate, RuleActionCollect:
		default:
			errs = append(errs, errors.New("override_action must be detect, terminate, or collect"))
		}
	}
	if m.OverrideMaxAlerts != nil {
		if *m.OverrideMaxAlerts == 0 {
			errs = append(errs, errors.New("override_max_alerts: 0 is not allowed; use override_action: collect or disable: true"))
		} else if err := ValidateMaxAlertsBound(*m.OverrideMaxAlerts, "override_max_alerts"); err != nil {
			errs = append(errs, err)
		}
	}
	for i, matcher := range m.AddTargetExclude {
		if strings.TrimSpace(matcher.ProviderHost) == "" && strings.TrimSpace(matcher.Path) == "" {
			errs = append(errs, fmt.Errorf("add_target_exclude[%d] must set provider_host or path", i))
		}
	}

	return errors.Join(errs...)
}

func ValidateMaxAlertsBound(value int, fieldName string) error {
	if value < 0 {
		return fmt.Errorf("%s must be non-negative", fieldName)
	}
	if value > MaxAlertsHardCeiling {
		return fmt.Errorf("%s must be <= %d", fieldName, MaxAlertsHardCeiling)
	}
	return nil
}
