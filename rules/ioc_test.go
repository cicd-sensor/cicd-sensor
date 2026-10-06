//go:build rules_validation

package rules_test

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestSubqlCommonManifestCacheLoaderExecRule(t *testing.T) {
	t.Parallel()

	loaded, err := rulesource.LoadRulesFile("ioc.yaml")
	if err != nil {
		t.Fatalf("load ioc rules: %v", err)
	}
	if len(loaded.RuleSets) != 1 {
		t.Fatalf("expected 1 ruleset, got %d", len(loaded.RuleSets))
	}
	set := loaded.RuleSets[0]

	var target rule.Rule
	for _, candidate := range set.Rules {
		if candidate.RuleID == "subql_common_manifest_cache_loader_exec" {
			target = candidate
			break
		}
	}
	if target.RuleID == "" {
		t.Fatal("subql_common_manifest_cache_loader_exec rule not present in shipped ruleset")
	}
	if target.EventType != jobevent.ProcessExec {
		t.Fatalf("event_type=%q, want %q", target.EventType, jobevent.ProcessExec)
	}
	if target.Action != rule.RuleActionTerminate {
		t.Fatalf("action=%q, want %q", target.Action, rule.RuleActionTerminate)
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

	npmLineage := []celengine.CELAncestor{
		{ExecPath: "/bin/sh", Argv: []string{"sh", "-c", "node ./dist/project/readers/manifest-cache.js"}},
		{ExecPath: "/usr/bin/node", Argv: []string{"npm", "install"}},
	}

	tests := []struct {
		name      string
		input     celengine.CELInputEvent
		wantMatch bool
	}{
		{
			name: "terminates the postinstall hook using the package-relative path",
			input: celengine.CELInputEvent{
				Process: celengine.NewCELProcess("/usr/bin/node", []string{"node", "./dist/project/readers/manifest-cache.js"}, npmLineage),
			},
			wantMatch: true,
		},
		{
			name: "terminates the detached --warm child using the absolute path",
			input: celengine.CELInputEvent{
				Process: celengine.NewCELProcess("/usr/bin/node", []string{"/usr/bin/node", "/home/runner/work/app/app/node_modules/@subql/common/dist/project/readers/manifest-cache.js", "--warm"}, nil),
			},
			wantMatch: true,
		},
		{
			name: "terminates the npm sh -c wrapper one exec earlier",
			input: celengine.CELInputEvent{
				Process: celengine.NewCELProcess("/bin/sh", []string{"sh", "-c", "node ./dist/project/readers/manifest-cache.js"}, nil),
			},
			wantMatch: true,
		},
		{
			name: "ignores legitimate sibling readers in the clean package",
			input: celengine.CELInputEvent{
				Process: celengine.NewCELProcess("/usr/bin/node", []string{"node", "./dist/project/readers/github-reader.js"}, npmLineage),
			},
		},
		{
			name: "ignores manifest-cache.js outside the package dist tree",
			input: celengine.CELInputEvent{
				Process: celengine.NewCELProcess("/usr/bin/node", []string{"node", "./scripts/manifest-cache.js", "--warm"}, nil),
			},
		},
		{
			name: "ignores a same-named source file that is not below dist",
			input: celengine.CELInputEvent{
				Process: celengine.NewCELProcess("/usr/bin/node", []string{"node", "./src/project/readers/manifest-cache.js"}, nil),
			},
		},
		{
			name: "ignores a process with no arguments",
			input: celengine.CELInputEvent{
				Process: celengine.NewCELProcess("/usr/bin/node", nil, nil),
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
