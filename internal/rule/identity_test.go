package rule_test

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestRuleIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		identity      rule.RuleIdentity
		wantZero      bool
		wantCanonical string
	}{
		{
			name:          "empty",
			wantZero:      true,
			wantCanonical: "/",
		},
		{
			name:          "flat ruleset",
			identity:      rule.RuleIdentity{RulesetID: "set", RuleID: "rule"},
			wantCanonical: "set/rule",
		},
		{
			name:          "slash containing ruleset",
			identity:      rule.RuleIdentity{RulesetID: "acme/security", RuleID: "curl_egress"},
			wantCanonical: "acme/security/curl_egress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.identity.IsZero(); got != tt.wantZero {
				t.Fatalf("IsZero: got %v, want %v", got, tt.wantZero)
			}
			canonical := tt.identity.CanonicalRuleID()
			if got := canonical.String(); got != tt.wantCanonical {
				t.Fatalf("CanonicalRuleID: got %q, want %q", got, tt.wantCanonical)
			}
		})
	}
}
