package rule_test

import (
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestValidateMaxAlertsBound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		value       int
		fieldName   string
		wantErrText string
	}{
		{
			name:        "negative is rejected",
			value:       -1,
			fieldName:   "max_alerts",
			wantErrText: "max_alerts must be non-negative",
		},
		{
			name:      "zero is allowed (means unset)",
			value:     0,
			fieldName: "max_alerts",
		},
		{
			name:      "ceiling itself is allowed",
			value:     rule.MaxAlertsHardCeiling,
			fieldName: "max_alerts",
		},
		{
			name:        "above ceiling is rejected",
			value:       rule.MaxAlertsHardCeiling + 1,
			fieldName:   "max_alerts",
			wantErrText: "max_alerts must be <= 100",
		},
		{
			name:        "field name is preserved in error",
			value:       -1,
			fieldName:   "default_max_alerts_per_rule",
			wantErrText: "default_max_alerts_per_rule must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rule.ValidateMaxAlertsBound(tt.value, tt.fieldName)
			if tt.wantErrText == "" {
				if err != nil {
					t.Fatalf("got error %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("got nil, want error containing %q", tt.wantErrText)
			}
			if !strings.Contains(err.Error(), tt.wantErrText) {
				t.Fatalf("error: got %q, want substring %q", err.Error(), tt.wantErrText)
			}
		})
	}
}

func TestResolveMaxAlertsCap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		ruleValue         int
		configuredDefault int
		wantFinal         int
		wantFellBack      bool
	}{
		{
			name:              "rule value wins when in range",
			ruleValue:         5,
			configuredDefault: 50,
			wantFinal:         5,
		},
		{
			name:              "configured default applies when rule unset",
			ruleValue:         0,
			configuredDefault: 30,
			wantFinal:         30,
		},
		{
			name:              "system default applies when both unset",
			ruleValue:         0,
			configuredDefault: 0,
			wantFinal:         rule.DefaultMaxAlertsPerRule,
		},
		{
			name:              "rule value at ceiling is accepted",
			ruleValue:         rule.MaxAlertsHardCeiling,
			configuredDefault: 0,
			wantFinal:         rule.MaxAlertsHardCeiling,
		},
		{
			name:              "rule value above ceiling falls back with warning",
			ruleValue:         rule.MaxAlertsHardCeiling + 1,
			configuredDefault: 50,
			wantFinal:         rule.DefaultMaxAlertsPerRule,
			wantFellBack:      true,
		},
		{
			name:              "negative rule value falls back with warning",
			ruleValue:         -1,
			configuredDefault: 50,
			wantFinal:         rule.DefaultMaxAlertsPerRule,
			wantFellBack:      true,
		},
		{
			name:              "configured default above ceiling falls back when rule is unset",
			ruleValue:         0,
			configuredDefault: rule.MaxAlertsHardCeiling + 1,
			wantFinal:         rule.DefaultMaxAlertsPerRule,
			wantFellBack:      true,
		},
		{
			name:              "negative configured default falls back when rule is unset",
			ruleValue:         0,
			configuredDefault: -1,
			wantFinal:         rule.DefaultMaxAlertsPerRule,
			wantFellBack:      true,
		},
		{
			name:              "in-range rule wins even when configured default is bad",
			ruleValue:         20,
			configuredDefault: rule.MaxAlertsHardCeiling + 1,
			wantFinal:         20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFinal, gotFellBack := rule.ResolveMaxAlertsCap(tt.ruleValue, tt.configuredDefault)
			if gotFinal != tt.wantFinal {
				t.Fatalf("final: got %d, want %d", gotFinal, tt.wantFinal)
			}
			if gotFellBack != tt.wantFellBack {
				t.Fatalf("fellBack: got %v, want %v", gotFellBack, tt.wantFellBack)
			}
		})
	}
}

func TestRuleTargetIsZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target rule.RuleTarget
		want   bool
	}{
		{name: "empty", target: rule.RuleTarget{}, want: true},
		{name: "include", target: rule.RuleTarget{Include: []rule.RuleTargetMatcher{{ProviderHost: "github.com"}}}},
		{name: "exclude", target: rule.RuleTarget{Exclude: []rule.RuleTargetMatcher{{Path: "acme/repo"}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.target.IsZero(); got != tt.want {
				t.Fatalf("IsZero: got %v, want %v", got, tt.want)
			}
		})
	}
}
