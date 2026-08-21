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

func TestRustBuildRules(t *testing.T) {
	t.Parallel()

	loaded, err := rulesource.LoadRulesFile("generic-execution.yaml")
	if err != nil {
		t.Fatalf("load execution rules: %v", err)
	}
	if len(loaded.RuleSets) != 1 {
		t.Fatalf("expected 1 ruleset, got %d", len(loaded.RuleSets))
	}
	set := loaded.RuleSets[0]

	byID := make(map[string]rule.Rule, len(set.Rules))
	for _, r := range set.Rules {
		byID[r.RuleID] = r
	}

	env, err := celengine.NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	// Lineage observed for the August 2026 proc-macro1 dropper: cargo runs the
	// compiled build script directly, and the detached /tmp payload still
	// reports build-script-build as its immediate ancestor at exec time.
	buildScriptLineage := []celengine.CELAncestor{
		{ExecPath: "/home/runner/work/app/app/target/debug/build/proc-macro1-0c1d2e3f/build-script-build", Argv: []string{"build-script-build"}},
		{ExecPath: "/home/runner/.cargo/bin/cargo", Argv: []string{"cargo", "build"}},
	}
	rustcLineage := []celengine.CELAncestor{
		{ExecPath: "/home/runner/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc", Argv: []string{"rustc", "--crate-name", "app"}},
		{ExecPath: "/home/runner/.cargo/bin/cargo", Argv: []string{"cargo", "build"}},
	}
	cargoOnlyLineage := []celengine.CELAncestor{
		{ExecPath: "/home/runner/.cargo/bin/cargo", Argv: []string{"cargo", "test"}},
	}

	cases := []struct {
		name      string
		ruleID    string
		input     celengine.CELInputEvent
		wantMatch bool
	}{
		{
			name:      "detects the dropper payload spawned from build-script-build",
			ruleID:    "rust_build_staged_payload_exec",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/tmp/rust-setup", []string{"/tmp/rust-setup", "23.254.165.112:443"}, buildScriptLineage)},
			wantMatch: true,
		},
		{
			name:      "matches a custom-named build script binary",
			ruleID:    "rust_build_staged_payload_exec",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/var/tmp/stage", nil, []celengine.CELAncestor{{ExecPath: "/work/target/release/build/foo-1234/build-script-gen"}})},
			wantMatch: true,
		},
		{
			name:      "matches /dev/shm execution below a proc-macro host rustc",
			ruleID:    "rust_build_staged_payload_exec",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/dev/shm/x", nil, rustcLineage)},
			wantMatch: true,
		},
		{
			name:      "matches memfd execution below a build script",
			ruleID:    "rust_build_staged_payload_exec",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/memfd:payload (deleted)", nil, buildScriptLineage), IsMemfd: true},
			wantMatch: true,
		},
		{
			name:      "ignores toolchain binaries spawned by a build script",
			ruleID:    "rust_build_staged_payload_exec",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/usr/bin/cc", []string{"cc", "-O2"}, buildScriptLineage)},
			wantMatch: false,
		},
		{
			name:      "ignores /tmp execution without build script or rustc ancestry",
			ruleID:    "rust_build_staged_payload_exec",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/tmp/rust-setup", nil, cargoOnlyLineage)},
			wantMatch: false,
		},
		{
			name:      "ignores rustdoc doctest binaries run from /tmp",
			ruleID:    "rust_build_staged_payload_exec",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/tmp/rustdoctestabc123/rust_out", nil, []celengine.CELAncestor{{ExecPath: "/home/runner/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustdoc"}, {ExecPath: "/home/runner/.cargo/bin/cargo", Argv: []string{"cargo", "test", "--doc"}}})},
			wantMatch: false,
		},
		{
			name:      "ignores a build-script- path fragment outside a cargo build directory",
			ruleID:    "rust_build_staged_payload_exec",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/tmp/tool", nil, []celengine.CELAncestor{{ExecPath: "/opt/build-script-runner/bin/run"}})},
			wantMatch: false,
		},
		{
			name:      "ignores /tmp-prefixed paths outside the staged directories",
			ruleID:    "rust_build_staged_payload_exec",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/tmpfs/bin/tool", nil, buildScriptLineage)},
			wantMatch: false,
		},
		{
			name:      "collects the payload download performed by the build script itself",
			ruleID:    "rust_build_egress",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/work/target/debug/build/proc-macro1-0c1d/build-script-build", nil, nil), RemoteIP: "23.254.165.112", RemotePort: 9089, Protocol: "tcp", Family: "ipv4"},
			wantMatch: true,
		},
		{
			name:      "collects the C2 beacon from the detached payload below the build script",
			ruleID:    "rust_build_egress",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/tmp/rust-setup", nil, buildScriptLineage), RemoteIP: "23.254.165.112", RemotePort: 443, Protocol: "tcp", Family: "ipv4"},
			wantMatch: true,
		},
		{
			name:      "collects IPv6 egress below rustc",
			ruleID:    "rust_build_egress",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/usr/bin/curl", nil, rustcLineage), RemoteIP: "2001:db8::1", RemotePort: 443, Protocol: "tcp", Family: "ipv6"},
			wantMatch: true,
		},
		{
			name:      "ignores loopback connections from a build script",
			ruleID:    "rust_build_egress",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/work/target/debug/build/x-1/build-script-build", nil, nil), RemoteIP: "127.0.0.1", RemotePort: 8080, Protocol: "tcp", Family: "ipv4"},
			wantMatch: false,
		},
		{
			name:      "ignores IPv6 loopback connections from a build script",
			ruleID:    "rust_build_egress",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/work/target/debug/build/x-1/build-script-build", nil, nil), RemoteIP: "::1", RemotePort: 8080, Protocol: "tcp", Family: "ipv6"},
			wantMatch: false,
		},
		{
			name:      "ignores IPv4-mapped loopback connections from a build script",
			ruleID:    "rust_build_egress",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/work/target/debug/build/x-1/build-script-build", nil, nil), RemoteIP: "::ffff:127.0.0.1", RemotePort: 5432, Protocol: "tcp", Family: "ipv6"},
			wantMatch: false,
		},
		{
			name:      "ignores cargo registry fetches without build script lineage",
			ruleID:    "rust_build_egress",
			input:     celengine.CELInputEvent{Process: celengine.NewCELProcess("/home/runner/.cargo/bin/cargo", []string{"cargo", "build"}, nil), RemoteIP: "104.16.1.1", RemotePort: 443, Protocol: "tcp", Family: "ipv4"},
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.ruleID+"/"+tc.name, func(t *testing.T) {
			t.Parallel()

			r, ok := byID[tc.ruleID]
			if !ok {
				t.Fatalf("rule %q not present in shipped ruleset", tc.ruleID)
			}
			prog, err := env.Compile(r.RuleID, r.EventType, r.Condition, set.Lists)
			if err != nil {
				t.Fatalf("compile %s: %v", r.RuleID, err)
			}
			staticActivation, err := celengine.NewListActivation(rule.NormalizePredefinedLists(set.Lists))
			if err != nil {
				t.Fatalf("list activation: %v", err)
			}
			matched, err := prog.EvalActivation(celengine.NewEventActivation(tc.input).WithParent(staticActivation))
			if err != nil {
				t.Fatalf("eval %s: %v", r.RuleID, err)
			}
			if matched != tc.wantMatch {
				t.Fatalf("rule %s matched=%v, want %v", r.RuleID, matched, tc.wantMatch)
			}
		})
	}

	wantActions := map[string]rule.RuleAction{
		"rust_build_staged_payload_exec": rule.RuleActionDetect,
		"rust_build_egress":              rule.RuleActionCollect,
	}
	for id, want := range wantActions {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("expected rule %q to be shipped", id)
		}
		if r.Action != want {
			t.Fatalf("rule %s action=%q, want %q", id, r.Action, want)
		}
	}
}
