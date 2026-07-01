package rulesource_test

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// TestPersistenceRulesCoverMoveAndLinkBypass is the regression guard for
// issue #107: protected-path persistence rules must match across file_open,
// file_move (mv / rename), and file_link (ln) so that staging a payload and
// then renaming or linking it into a protected location is not a detection
// blind spot. It loads the actually shipped baseline ruleset and evaluates
// the real rule conditions, so it fails if a rule is removed or narrowed.
func TestPersistenceRulesCoverMoveAndLinkBypass(t *testing.T) {
	t.Parallel()

	loaded, err := rulesource.LoadRulesFile("../../rules/generic-persistence.yaml")
	if err != nil {
		t.Fatalf("load persistence rules: %v", err)
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

	cases := []struct {
		ruleID    string
		input     celengine.CELInputEvent
		wantMatch bool
	}{
		// Cron: write, rename, and link into /etc/cron.d all detect.
		{"cron_write", celengine.CELInputEvent{Path: "/etc/cron.d/evil", IsWrite: true}, true},
		{"cron_write", celengine.CELInputEvent{Path: "/etc/crontab", IsWrite: true}, true},
		{"cron_write", celengine.CELInputEvent{Path: "/etc/cron.d/evil", IsWrite: false}, false},
		{"cron_move", celengine.CELInputEvent{FromPath: "/tmp/job", ToPath: "/etc/cron.d/evil"}, true},
		{"cron_move", celengine.CELInputEvent{FromPath: "/tmp/a", ToPath: "/tmp/b"}, false},
		{"cron_link", celengine.CELInputEvent{CreatedPath: "/etc/cron.d/evil", ExistingPath: "/tmp/job", IsSymlink: true}, true},

		// Shell startup files.
		{"shell_rc_write", celengine.CELInputEvent{Path: "/home/runner/.bashrc", IsWrite: true}, true},
		{"shell_rc_write", celengine.CELInputEvent{Path: "/etc/profile.d/evil.sh", IsWrite: true}, true},
		{"shell_rc_move", celengine.CELInputEvent{FromPath: "/tmp/rc", ToPath: "/home/runner/.bashrc"}, true},
		{"shell_rc_link", celengine.CELInputEvent{CreatedPath: "/home/runner/.zshrc", ExistingPath: "/tmp/rc", IsSymlink: true}, true},

		// Dynamic linker preload.
		{"ld_so_preload_write", celengine.CELInputEvent{Path: "/etc/ld.so.preload", IsWrite: true}, true},
		{"ld_so_preload_move", celengine.CELInputEvent{FromPath: "/tmp/p", ToPath: "/etc/ld.so.preload"}, true},
		{"ld_so_preload_link", celengine.CELInputEvent{CreatedPath: "/etc/ld.so.conf.d/evil.conf", ExistingPath: "/tmp/p", IsHardlink: true}, true},

		// User systemd service unit (same move/link gap closed).
		{"user_systemd_service_move", celengine.CELInputEvent{FromPath: "/tmp/x.service", ToPath: "/home/runner/.config/systemd/user/x.service"}, true},
		{"user_systemd_service_link", celengine.CELInputEvent{CreatedPath: "/home/runner/.config/systemd/user/x.service", ExistingPath: "/tmp/x.service", IsSymlink: true}, true},
	}

	for _, tc := range cases {
		t.Run(tc.ruleID+"/"+caseLabel(tc.input), func(t *testing.T) {
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

	// Guard the event-type coverage explicitly: each persistence category
	// must ship a rule for every primitive an attacker can reach it through.
	for _, ids := range [][3]string{
		{"cron_write", "cron_move", "cron_link"},
		{"shell_rc_write", "shell_rc_move", "shell_rc_link"},
		{"ld_so_preload_write", "ld_so_preload_move", "ld_so_preload_link"},
	} {
		wantType := map[string]jobevent.Type{
			ids[0]: jobevent.FileOpen,
			ids[1]: jobevent.FileMove,
			ids[2]: jobevent.FileLink,
		}
		for id, want := range wantType {
			r, ok := byID[id]
			if !ok {
				t.Fatalf("expected rule %q to be shipped", id)
			}
			if r.EventType != want {
				t.Fatalf("rule %q event_type=%q, want %q", id, r.EventType, want)
			}
		}
	}
}

func caseLabel(in celengine.CELInputEvent) string {
	switch {
	case in.ToPath != "":
		return "to=" + in.ToPath
	case in.CreatedPath != "":
		return "link=" + in.CreatedPath
	default:
		return "path=" + in.Path
	}
}
