//go:build rules_validation

package rules_test

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestGitHubActionsNovember2026Rules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		file      string
		ruleID    string
		eventType jobevent.Type
		action    rule.RuleAction
		cases     []struct {
			name  string
			input celengine.CELInputEvent
			want  bool
		}
	}{
		{
			name: "campaign_ip", file: "ioc.yaml",
			ruleID:    "github_actions_nov2026_exfiltration_ip",
			eventType: jobevent.NetworkConnect, action: rule.RuleActionTerminate,
			cases: []struct {
				name  string
				input celengine.CELInputEvent
				want  bool
			}{
				{"first_reported_endpoint", celengine.CELInputEvent{RemoteIP: "18.143.168.96", RemotePort: 8080, Protocol: "tcp", Family: "ipv4"}, true},
				{"second_reported_endpoint", celengine.CELInputEvent{RemoteIP: "194.150.166.244", RemotePort: 8080, Protocol: "tcp", Family: "ipv4"}, true},
				{"changed_port_still_matches_ioc", celengine.CELInputEvent{RemoteIP: "18.143.168.96", RemotePort: 443, Protocol: "tcp", Family: "ipv4"}, true},
				{"neighboring_ip_is_not_ioc", celengine.CELInputEvent{RemoteIP: "18.143.168.97", RemotePort: 8080, Protocol: "tcp", Family: "ipv4"}, false},
				{"ipv6_is_outside_exact_ipv4_ioc", celengine.CELInputEvent{RemoteIP: "::ffff:18.143.168.96", RemotePort: 8080, Protocol: "tcp", Family: "ipv6"}, false},
				{"zero_event_does_not_match", celengine.CELInputEvent{}, false},
			},
		},
		{
			name: "telegram_domain", file: "generic-exfiltration.yaml",
			ruleID:    "telegram_bot_api_domain",
			eventType: jobevent.Domain, action: rule.RuleActionDetect,
			// Domain events are lowercased and have their trailing dot removed before evaluation.
			cases: []struct {
				name  string
				input celengine.CELInputEvent
				want  bool
			}{
				{"api_dns_query_is_detect_only_without_http_fields", celengine.CELInputEvent{Domain: "api.telegram.org", Source: "dns"}, true},
				{"parent_domain_is_not_api", celengine.CELInputEvent{Domain: "telegram.org", Source: "dns"}, false},
				{"subdomain_is_not_exact_api_domain", celengine.CELInputEvent{Domain: "files.api.telegram.org", Source: "dns"}, false},
				{"lookalike_suffix_is_not_telegram", celengine.CELInputEvent{Domain: "api.telegram.org.example.com", Source: "dns"}, false},
				{"lookalike_prefix_is_not_telegram", celengine.CELInputEvent{Domain: "evilapi.telegram.org", Source: "dns"}, false},
				{"zero_event_does_not_match", celengine.CELInputEvent{}, false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			loaded, err := rulesource.LoadRulesFile(tt.file)
			if err != nil {
				t.Fatalf("load rules: %v", err)
			}
			if len(loaded.RuleSets) != 1 {
				t.Fatalf("expected one ruleset, got %d", len(loaded.RuleSets))
			}
			set := loaded.RuleSets[0]
			var target rule.Rule
			for _, candidate := range set.Rules {
				if candidate.RuleID == tt.ruleID {
					target = candidate
					break
				}
			}
			if target.RuleID == "" {
				t.Fatalf("rule %q missing from shipped rules", tt.ruleID)
			}
			if target.EventType != tt.eventType || target.Action != tt.action {
				t.Fatalf("event/action=%q/%q, want %q/%q", target.EventType, target.Action, tt.eventType, tt.action)
			}
			env, err := celengine.NewEnv()
			if err != nil {
				t.Fatalf("new env: %v", err)
			}
			prog, err := env.Compile(target.RuleID, target.EventType, target.Condition, set.Lists)
			if err != nil {
				t.Fatalf("compile rule: %v", err)
			}
			for _, tc := range tt.cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					got, err := prog.EvalActivation(celengine.NewEventActivation(tc.input))
					if err != nil {
						t.Fatalf("evaluate rule: %v", err)
					}
					if got != tc.want {
						t.Fatalf("matched=%v, want %v", got, tc.want)
					}
				})
			}
		})
	}
}
