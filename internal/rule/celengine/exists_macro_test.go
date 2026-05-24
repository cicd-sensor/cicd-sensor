package celengine

import (
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

// TestExistsMacroBehavioralCoverage exercises the .exists() syntactic
// space the rule corpus can produce: shapes the specialized macro folds
// into __hasAny* calls, shapes that fall through to the cel-go
// comprehension expansion, and shapes that should fail compile.
//
// The goal is not to verify which rewrite path runs (the bench data
// already confirms the macro fires); it is to confirm semantic
// equivalence so future macro changes cannot silently break a pattern
// rule authors may write. Each case is described in terms of how the
// macro evaluates its match-or-fall-through gate; see
// expandSpecializedExists for the gate code.
func TestExistsMacroBehavioralCoverage(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	tests := []struct {
		name      string
		eventType jobevent.Type
		source    string
		input     CELInputEvent
		lists     map[string][]string
		wantMatch bool
	}{
		// --- Specialized rewrite paths (macro produces __hasAny*) ---

		{
			name:      "specialize/endsWith/field_target_hit_first",
			eventType: jobevent.ProcessExec,
			source:    `list.shells.exists(b, process.exec_path.endsWith(b))`,
			input:     CELInputEvent{Process: NewCELProcess("/bin/bash", nil, nil)},
			lists:     map[string][]string{"shells": {"/bash", "/sh", "/zsh"}},
			wantMatch: true,
		},
		{
			name:      "specialize/endsWith/field_target_hit_last",
			eventType: jobevent.ProcessExec,
			source:    `list.shells.exists(b, process.exec_path.endsWith(b))`,
			input:     CELInputEvent{Process: NewCELProcess("/bin/zsh", nil, nil)},
			lists:     map[string][]string{"shells": {"/bash", "/sh", "/zsh"}},
			wantMatch: true,
		},
		{
			name:      "specialize/endsWith/no_hit",
			eventType: jobevent.ProcessExec,
			source:    `list.shells.exists(b, process.exec_path.endsWith(b))`,
			input:     CELInputEvent{Process: NewCELProcess("/usr/bin/curl", nil, nil)},
			lists:     map[string][]string{"shells": {"/bash", "/sh"}},
			wantMatch: false,
		},
		{
			name:      "specialize/endsWith/empty_list_returns_false",
			eventType: jobevent.ProcessExec,
			source:    `list.shells.exists(b, process.exec_path.endsWith(b))`,
			input:     CELInputEvent{Process: NewCELProcess("/bin/bash", nil, nil)},
			lists:     map[string][]string{"shells": {}},
			wantMatch: false,
		},
		{
			name:      "specialize/startsWith/path_variable_target",
			eventType: jobevent.FileOpen,
			source:    `list.dirs.exists(d, path.startsWith(d))`,
			input:     CELInputEvent{Path: "/etc/passwd"},
			lists:     map[string][]string{"dirs": {"/var/", "/etc/", "/root/"}},
			wantMatch: true,
		},
		{
			name:      "specialize/contains/literal_target",
			eventType: jobevent.FileOpen,
			source:    `list.markers.exists(m, "/var/lib/apt/lists/partial/cached".contains(m))`,
			input:     CELInputEvent{Path: "/anything"},
			lists:     map[string][]string{"markers": {"apt", "yum"}},
			wantMatch: true,
		},
		{
			name:      "specialize/iterator_name_arbitrary",
			eventType: jobevent.ProcessExec,
			source:    `list.suffixes.exists(needle, process.exec_path.endsWith(needle))`,
			input:     CELInputEvent{Process: NewCELProcess("/bin/bash", nil, nil)},
			lists:     map[string][]string{"suffixes": {"sh", "bash"}},
			wantMatch: true,
		},
		{
			name:      "specialize/contains/domain_target",
			eventType: jobevent.Domain,
			source:    `list.suspicious.exists(s, domain.contains(s))`,
			input:     CELInputEvent{Domain: "host.evil.example.com"},
			lists:     map[string][]string{"suspicious": {".evil.", ".bad."}},
			wantMatch: true,
		},

		// --- Fall-through paths (macro defers to parser.MakeExists) ---

		{
			name:      "fallthrough/equality_with_literal",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(a, a == "--token")`,
			input:     CELInputEvent{Process: NewCELProcess("/usr/bin/curl", []string{"curl", "--token", "abc"}, nil)},
			wantMatch: true,
		},
		{
			name:      "fallthrough/method_with_literal_argument",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(a, a.contains("password"))`,
			input:     CELInputEvent{Process: NewCELProcess("/usr/bin/curl", []string{"--password=secret"}, nil)},
			wantMatch: true,
		},
		{
			name:      "fallthrough/method_arg_is_other_iter_var",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(a, process.ancestors.exists(p, p.exec_path.endsWith(a)))`,
			input: CELInputEvent{Process: NewCELProcess("/usr/bin/python", []string{"sh"}, []CELAncestor{
				{ExecPath: "/bin/sh"},
			})},
			wantMatch: true,
		},
		{
			name:      "fallthrough/body_is_and_expression",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(a, a.startsWith("--") && a.contains("token"))`,
			input:     CELInputEvent{Process: NewCELProcess("/usr/bin/curl", []string{"--auth-token=abc"}, nil)},
			wantMatch: true,
		},
		{
			name:      "fallthrough/body_is_logical_not",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(a, !a.startsWith("/"))`,
			input:     CELInputEvent{Process: NewCELProcess("/bin/sh", []string{"/bin/sh", "user@host"}, nil)},
			wantMatch: true,
		},
		{
			name:      "fallthrough/body_is_or_expression",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(a, a == "--quiet" || a == "--silent")`,
			input:     CELInputEvent{Process: NewCELProcess("/usr/bin/curl", []string{"--silent"}, nil)},
			wantMatch: true,
		},
		// `list.flags.exists(b, b)` is not testable here: CEL needs the
		// body to be bool, and string is not implicitly coercible. Same
		// for `a.contains(a, a)` (no such overload). Both surface as
		// compile / eval errors and are covered in TestExistsMacroCompileErrors.

		// --- Nested .exists ---

		{
			name:      "nested/inner_specializes_outer_falls_through",
			eventType: jobevent.ProcessExec,
			source: `process.argv.exists(a,
                list.needles.exists(s, a.contains(s)))`,
			input: CELInputEvent{Process: NewCELProcess("/usr/bin/curl", []string{
				"curl", "--password=secret-token",
			}, nil)},
			lists:     map[string][]string{"needles": {"token", "key"}},
			wantMatch: true,
		},
		{
			name:      "nested/inner_fall_through_outer_fall_through",
			eventType: jobevent.ProcessExec,
			source: `process.ancestors.exists(p,
                p.argv.exists(a, a.contains("token")))`,
			input: CELInputEvent{Process: NewCELProcess("/usr/bin/python", nil, []CELAncestor{
				{ExecPath: "/bin/sh", Argv: []string{"sh", "-c", "curl --token=x"}},
			})},
			wantMatch: true,
		},
		{
			name:      "nested/three_levels",
			eventType: jobevent.ProcessExec,
			source: `process.ancestors.exists(a,
                a.argv.exists(arg,
                    list.suspicious.exists(s, arg.contains(s))))`,
			input: CELInputEvent{Process: NewCELProcess("/usr/bin/python", nil, []CELAncestor{
				{ExecPath: "/bin/sh", Argv: []string{"sh", "-c", "curl --secret=abc"}},
			})},
			lists:     map[string][]string{"suspicious": {"secret"}},
			wantMatch: true,
		},

		// --- Degenerate cases (correctness preserved by fall-through guards) ---

		{
			// exprReferencesIdent guard catches the iter-var-in-receiver case;
			// rewriting would dangle a reference to `p` outside the comprehension.
			name:      "degenerate/iter_var_on_both_sides_falls_through",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(p, p.endsWith(p))`,
			input:     CELInputEvent{Process: NewCELProcess("/bin/sh", []string{"a", "b", "ab"}, nil)},
			wantMatch: true, // every string ends with itself
		},
		{
			// Outer and inner iter var share a name; cel-go scoping picks the
			// innermost binding for the inner body. Inner falls through (literal
			// arg) so we exercise scope tracking without macro specialization.
			name:      "degenerate/shadowing_iter_var_name",
			eventType: jobevent.ProcessExec,
			source: `process.argv.exists(a,
                process.ancestors.exists(a, a.exec_path.endsWith("/bash")))`,
			input: CELInputEvent{Process: NewCELProcess("/usr/bin/python", []string{"x"}, []CELAncestor{
				{ExecPath: "/bin/bash"},
			})},
			wantMatch: true,
		},
		{
			// receiver is the iter var itself; macro requires receiver != iter
			// var so this falls through and runs as a normal comprehension.
			// Inputs use lowercase to dodge string literal normalization
			// (literals are NFC + lowercased; raw argv is not).
			name:      "degenerate/method_target_is_iter_var",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(a, a.contains("xtra"))`,
			input:     CELInputEvent{Process: NewCELProcess("/bin/sh", []string{"sh", "xtra-arg"}, nil)},
			wantMatch: true,
		},

		// --- Variable iteration sources (not just predefined lists) ---

		{
			name:      "source/process_argv_iteration",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(a, a == "--root")`,
			input:     CELInputEvent{Process: NewCELProcess("/usr/bin/cmd", []string{"cmd", "--root"}, nil)},
			wantMatch: true,
		},
		{
			name:      "source/process_ancestors_iteration",
			eventType: jobevent.ProcessExec,
			source: `process.ancestors.exists(a,
                a.exec_path.endsWith("/bash"))`,
			input: CELInputEvent{Process: NewCELProcess("/usr/bin/curl", nil, []CELAncestor{
				{ExecPath: "/usr/bin/python"}, {ExecPath: "/bin/bash"},
			})},
			wantMatch: true,
		},
		{
			name:      "source/empty_argv_returns_false",
			eventType: jobevent.ProcessExec,
			source:    `process.argv.exists(a, a == "anything")`,
			input:     CELInputEvent{Process: NewCELProcess("/bin/sh", nil, nil)},
			wantMatch: false,
		},
		{
			name:      "source/empty_ancestors_returns_false",
			eventType: jobevent.ProcessExec,
			source:    `process.ancestors.exists(a, a.exec_path.endsWith("/bash"))`,
			input:     CELInputEvent{Process: NewCELProcess("/bin/sh", nil, nil)},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lists := rule.NormalizePredefinedLists(tt.lists)
			prog, err := env.Compile("rule-id", tt.eventType, tt.source, lists)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			staticActivation, err := NewListActivation(lists)
			if err != nil {
				t.Fatalf("list activation: %v", err)
			}
			matched, err := prog.EvalActivation(NewEventActivation(tt.input).WithParent(staticActivation))
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if matched != tt.wantMatch {
				t.Fatalf("matched = %v, want %v", matched, tt.wantMatch)
			}
		})
	}
}

// TestExistsMacroCompileErrors locks in the shapes the env intentionally
// rejects. These rules cannot be written today; if any of them start to
// compile, either denyCallValidator's blocklist has loosened or
// ClearMacros has been weakened — both worth catching in code review.
func TestExistsMacroCompileErrors(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	tests := []struct {
		name       string
		eventType  jobevent.Type
		source     string
		errPattern string
	}{
		{
			// Macro arity is fixed at 2; cel-go reports the macro signature.
			name:       "wrong_arity_too_few",
			eventType:  jobevent.ProcessExec,
			source:     `process.argv.exists(a)`,
			errPattern: "exists",
		},
		{
			// `matches` is in denyCallValidator's forbidden set. The
			// comprehension itself would parse fine, but the validator pass
			// rejects the regex method.
			name:       "matches_in_body_is_denied",
			eventType:  jobevent.ProcessExec,
			source:     `process.argv.exists(a, a.matches("^--secret"))`,
			errPattern: "matches",
		},
		{
			// size() is in denyCallValidator's forbidden set.
			name:       "size_in_body_is_denied",
			eventType:  jobevent.ProcessExec,
			source:     `process.argv.exists(a, size(a) > 5)`,
			errPattern: "size",
		},
		{
			// Stdlib macros are cleared in NewEnv; only .exists is reinstated.
			// `.all(...)` should be undeclared.
			name:       "all_macro_is_not_registered",
			eventType:  jobevent.ProcessExec,
			source:     `process.argv.all(a, a.contains("x"))`,
			errPattern: "all",
		},
		{
			name:       "filter_macro_is_not_registered",
			eventType:  jobevent.ProcessExec,
			source:     `process.argv.filter(a, a.contains("x")).size() > 0`,
			errPattern: "filter",
		},
		{
			name:       "exists_one_macro_is_not_registered",
			eventType:  jobevent.ProcessExec,
			source:     `process.argv.exists_one(a, a.contains("x"))`,
			errPattern: "exists_one",
		},
		{
			// `has()` is cleared along with the other macros; CEL field
			// presence checking is not supported in our rule grammar.
			name:       "has_macro_is_not_registered",
			eventType:  jobevent.ProcessExec,
			source:     `has(process.exec_path)`,
			errPattern: "has",
		},
		{
			// Index operator is denied; correlation env allows it for
			// rule["X"] but single-event rules cannot index into argv.
			name:       "index_into_argv_is_denied",
			eventType:  jobevent.ProcessExec,
			source:     `process.argv[0] == "bash"`,
			errPattern: "_[_]",
		},
		{
			// Arithmetic is denied across the board.
			name:       "arithmetic_is_denied",
			eventType:  jobevent.NetworkConnect,
			source:     `remote_port + 1 == 81`,
			errPattern: "_+_",
		},
		{
			// String contains has only one binary overload (string,string);
			// `a.contains(a, a)` fails type-check with "no matching overload".
			name:       "method_with_too_many_args_fails_typecheck",
			eventType:  jobevent.ProcessExec,
			source:     `process.argv.exists(a, a.contains(a, a))`,
			errPattern: "no matching overload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := env.Compile("rule-id", tt.eventType, tt.source, nil)
			if err == nil {
				t.Fatalf("expected compile error containing %q, got nil", tt.errPattern)
			}
			if !strings.Contains(err.Error(), tt.errPattern) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.errPattern)
			}
		})
	}
}

// TestExistsMacroSemanticEquivalence pairs a specialize-eligible
// expression with a logically identical non-specialized rewrite and
// confirms both produce the same result. If the macro ever drifts from
// the stdlib comprehension semantics, these pairs catch it.
func TestExistsMacroSemanticEquivalence(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	inputs := []struct {
		name  string
		input CELInputEvent
	}{
		{"match_first", CELInputEvent{Process: NewCELProcess("/bin/bash", nil, nil)}},
		{"match_last", CELInputEvent{Process: NewCELProcess("/bin/zsh", nil, nil)}},
		{"no_match", CELInputEvent{Process: NewCELProcess("/usr/bin/curl", nil, nil)}},
		{"empty_path", CELInputEvent{Process: NewCELProcess("", nil, nil)}},
	}

	lists := rule.NormalizePredefinedLists(map[string][]string{
		"shells": {"/bash", "/sh", "/zsh"},
	})

	pairs := []struct {
		name        string
		specialized string
		fallback    string
	}{
		{
			name:        "endsWith",
			specialized: `list.shells.exists(b, process.exec_path.endsWith(b))`,
			// Same semantics expressed so the macro cannot specialize it:
			// `... && true` makes the body shape a binary _&&_ call, which
			// is not a member function so the macro falls through to the
			// stdlib comprehension expansion.
			fallback: `list.shells.exists(b, process.exec_path.endsWith(b) && true)`,
		},
	}

	for _, p := range pairs {
		specProg, err := env.Compile("spec", jobevent.ProcessExec, p.specialized, lists)
		if err != nil {
			t.Fatalf("compile specialized %s: %v", p.name, err)
		}
		fallProg, err := env.Compile("fall", jobevent.ProcessExec, p.fallback, lists)
		if err != nil {
			t.Fatalf("compile fallthrough %s: %v", p.name, err)
		}
		static, err := NewListActivation(lists)
		if err != nil {
			t.Fatalf("list activation: %v", err)
		}

		for _, in := range inputs {
			t.Run(p.name+"/"+in.name, func(t *testing.T) {
				specMatch, err := specProg.EvalActivation(NewEventActivation(in.input).WithParent(static))
				if err != nil {
					t.Fatalf("spec eval: %v", err)
				}
				fallMatch, err := fallProg.EvalActivation(NewEventActivation(in.input).WithParent(static))
				if err != nil {
					t.Fatalf("fall eval: %v", err)
				}
				if specMatch != fallMatch {
					t.Fatalf("divergence: specialized=%v fallthrough=%v", specMatch, fallMatch)
				}
			})
		}
	}
}
