package rulevalidate

import (
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
)

func TestCompileSetReportsBadRuleConditions(t *testing.T) {
	t.Parallel()

	env, err := celengine.NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	compileErrors := CompileSet(env, rule.RuleSet{
		RulesetID: "set-1",
		Lists: map[string][]string{
			"domains": {"EXAMPLE.COM"},
		},
		Rules: []rule.Rule{
			{
				RuleID:    "good",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip in list.domains`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "bad",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip.matches(".*")`,
				Action:    rule.RuleActionDetect,
			},
		},
	})

	if len(compileErrors) != 1 {
		t.Fatalf("compile error count: got %d, want 1", len(compileErrors))
	}
	if compileErrors[0].Identity != (rule.RuleIdentity{RulesetID: "set-1", RuleID: "bad"}) {
		t.Fatalf("compile error identity: got %#v, want set-1/bad", compileErrors[0].Identity)
	}
}

func TestCompileSetReportsBadExceptions(t *testing.T) {
	t.Parallel()

	env, err := celengine.NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	compileErrors := CompileSet(env, rule.RuleSet{
		RulesetID: "set-1",
		Rules: []rule.Rule{
			{
				RuleID:     "bad_exception",
				EventType:  jobevent.ProcessExec,
				Condition:  `process.exec_path.endsWith("/bash")`,
				Exceptions: `process.argv[0] == "bash"`,
				Action:     rule.RuleActionDetect,
			},
		},
	})

	if len(compileErrors) != 1 {
		t.Fatalf("compile error count: got %d, want 1", len(compileErrors))
	}
	if compileErrors[0].Identity != (rule.RuleIdentity{RulesetID: "set-1", RuleID: "bad_exception"}) {
		t.Fatalf("compile error identity: got %#v", compileErrors[0].Identity)
	}
	if compileErrors[0].Source != `process.argv[0] == "bash"` {
		t.Fatalf("compile error source: got %q", compileErrors[0].Source)
	}
}

func TestCompileSetReportsUndefinedPredefinedList(t *testing.T) {
	t.Parallel()

	env, err := celengine.NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	compileErrors := CompileSet(env, rule.RuleSet{
		RulesetID: "set-1",
		Lists: map[string][]string{
			"present": {"/bash"},
		},
		Rules: []rule.Rule{
			{
				RuleID:    "missing_list",
				EventType: jobevent.ProcessExec,
				Condition: `list.missing.exists(v, process.exec_path.endsWith(v))`,
				Action:    rule.RuleActionDetect,
			},
		},
	})

	if len(compileErrors) != 1 {
		t.Fatalf("compile error count: got %d, want 1", len(compileErrors))
	}
	if compileErrors[0].Identity != (rule.RuleIdentity{RulesetID: "set-1", RuleID: "missing_list"}) {
		t.Fatalf("compile error identity: got %#v", compileErrors[0].Identity)
	}
}

func TestCompileSetCompilesValidCorrelationRules(t *testing.T) {
	t.Parallel()

	env, err := celengine.NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	compileErrors := CompileSet(env, rule.RuleSet{
		RulesetID: "set-1",
		Rules: []rule.Rule{
			{
				RuleID:    "single",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "example.com"`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule.single.total_count >= 1`,
				Action:    rule.RuleActionDetect,
			},
		},
	})

	if len(compileErrors) != 0 {
		t.Fatalf("compile error count: got %d, want 0", len(compileErrors))
	}
}

func TestCompileSetReportsBadCorrelationRules(t *testing.T) {
	t.Parallel()

	env, err := celengine.NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	tests := []struct {
		name      string
		condition string
		want      string
	}{
		{
			name:      "missing_reference",
			condition: `rule.missing.total_count >= 1`,
			want:      `correlation reference "missing" does not exist`,
		},
		{
			name:      "event_variable_reference",
			condition: `process.exec_path.endsWith("/bash")`,
			want:      `undeclared reference to 'process'`,
		},
		{
			name:      "predefined_list_reference",
			condition: `rule.single.total_count >= 1 && "prod" in list.projects`,
			want:      `does not support field selection`,
		},
		{
			name:      "dynamic_index",
			condition: `rule[rule_id].total_count >= 1`,
			want:      `undeclared reference to 'rule_id'`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			compileErrors := CompileSet(env, rule.RuleSet{
				RulesetID: "set-1",
				Rules: []rule.Rule{
					{
						RuleID:    "single",
						EventType: jobevent.NetworkConnect,
						Condition: `remote_ip == "example.com"`,
						Action:    rule.RuleActionDetect,
					},
					{
						RuleID:    "corr",
						Type:      "correlation",
						Condition: tt.condition,
						Action:    rule.RuleActionDetect,
					},
				},
			})

			if len(compileErrors) != 1 {
				t.Fatalf("compile error count: got %d, want 1 (%#v)", len(compileErrors), compileErrors)
			}
			if compileErrors[0].Identity != (rule.RuleIdentity{RulesetID: "set-1", RuleID: "corr"}) {
				t.Fatalf("compile error identity: got %#v, want set-1/corr", compileErrors[0].Identity)
			}
			if compileErrors[0].Source != tt.condition {
				t.Fatalf("compile error source: got %q, want %q", compileErrors[0].Source, tt.condition)
			}
			if !strings.Contains(compileErrors[0].Reason, tt.want) {
				t.Fatalf("compile error reason: got %q, want substring %q", compileErrors[0].Reason, tt.want)
			}
		})
	}
}

func TestCompileSetSkipsWhitespaceOnlyExceptions(t *testing.T) {
	t.Parallel()

	env, err := celengine.NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	compileErrors := CompileSet(env, rule.RuleSet{
		RulesetID: "set-1",
		Rules: []rule.Rule{
			{
				RuleID:     "valid",
				EventType:  jobevent.ProcessExec,
				Condition:  `process.exec_path.endsWith("/bash")`,
				Exceptions: " \n\t ",
				Action:     rule.RuleActionDetect,
			},
		},
	})

	if len(compileErrors) != 0 {
		t.Fatalf("compile error count: got %d, want 0", len(compileErrors))
	}
}
