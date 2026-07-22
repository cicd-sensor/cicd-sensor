//go:build rules_validation

package rules_test

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestNodeInlineEvalDescendantUserDataScriptExecRule(t *testing.T) {
	t.Parallel()

	loaded, err := rulesource.LoadRulesFile("generic-execution.yaml")
	if err != nil {
		t.Fatalf("load execution rules: %v", err)
	}
	if len(loaded.RuleSets) != 1 {
		t.Fatalf("expected 1 ruleset, got %d", len(loaded.RuleSets))
	}
	set := loaded.RuleSets[0]

	var target rule.Rule
	for _, candidate := range set.Rules {
		if candidate.RuleID == "node_inline_eval_descendant_user_data_script_exec" {
			target = candidate
			break
		}
	}
	if target.RuleID == "" {
		t.Fatal("node_inline_eval_descendant_user_data_script_exec rule not present in shipped ruleset")
	}
	if target.EventType != jobevent.ProcessExec {
		t.Fatalf("event_type=%q, want %q", target.EventType, jobevent.ProcessExec)
	}
	if target.Action != rule.RuleActionDetect {
		t.Fatalf("action=%q, want %q", target.Action, rule.RuleActionDetect)
	}

	env, err := celengine.NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}
	prog, err := env.Compile(target.RuleID, target.EventType, target.Condition, set.Lists)
	if err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	staticActivation, err := celengine.NewListActivation(rule.NormalizePredefinedLists(set.Lists))
	if err != nil {
		t.Fatalf("list activation: %v", err)
	}

	tests := []struct {
		name      string
		input     celengine.CELInputEvent
		wantMatch bool
	}{
		{
			name: "detects inline eval staging a user data script",
			input: celengine.CELInputEvent{
				Process: celengine.NewCELProcess("/usr/bin/node", []string{"node", "/home/runner/.local/share/NodeJS/sync.js"}, []celengine.CELAncestor{
					{ExecPath: "/usr/bin/node", Argv: []string{"node", "-e", "downloader"}},
					{ExecPath: "/usr/bin/node", Argv: []string{"node", "app.js"}},
				}),
			},
			wantMatch: true,
		},
		{
			name: "requires inline eval in the ancestry",
			input: celengine.CELInputEvent{
				Process: celengine.NewCELProcess("/usr/bin/node", []string{"node", "/home/runner/.local/share/NodeJS/sync.js"}, []celengine.CELAncestor{
					{ExecPath: "/usr/bin/node", Argv: []string{"node", "npm-cli.js", "test"}},
				}),
			},
		},
		{
			name: "excludes project config scripts below inline eval",
			input: celengine.CELInputEvent{
				Process: celengine.NewCELProcess("/usr/bin/node", []string{"node", "/home/runner/work/project/.config/build.js"}, []celengine.CELAncestor{
					{ExecPath: "/usr/bin/node", Argv: []string{"node", "-e", "wrapper"}},
				}),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			matched, err := prog.EvalActivation(celengine.NewEventActivation(tc.input).WithParent(staticActivation))
			if err != nil {
				t.Fatalf("evaluate rule: %v", err)
			}
			if matched != tc.wantMatch {
				t.Fatalf("matched=%v, want %v", matched, tc.wantMatch)
			}
		})
	}
}
