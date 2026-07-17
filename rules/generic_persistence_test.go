//go:build rules_validation

package rules_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// TestPersistenceRulesCoverLandingBypasses is the regression guard for issues
// #107 and #108. Protected persistence locations must remain covered when a
// payload is written, moved, linked, or exposed through a mount alias. It loads
// the shipped baseline ruleset and evaluates the real rule conditions.
func TestPersistenceRulesCoverLandingBypasses(t *testing.T) {
	t.Parallel()

	loaded, err := rulesource.LoadRulesFile("generic-persistence.yaml")
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
		// Cron: write, rename, and link into /etc/cron.d all match.
		{"cron_write", celengine.CELInputEvent{Path: "/etc/cron.d/evil", IsWrite: true}, true},
		{"cron_write", celengine.CELInputEvent{Path: "/etc/crontab", IsWrite: true}, true},
		{"cron_write", celengine.CELInputEvent{Path: "/etc/cron.d/evil", IsWrite: false}, false},
		{"cron_write", celengine.CELInputEvent{Path: "/workspace/rootfs/etc/cron.d/fixture", IsWrite: true}, false},
		{"cron_move", celengine.CELInputEvent{FromPath: "/tmp/job", ToPath: "/etc/cron.d/evil"}, true},
		{"cron_move", celengine.CELInputEvent{FromPath: "/tmp/a", ToPath: "/tmp/b"}, false},
		{"cron_move", celengine.CELInputEvent{FromPath: "/tmp/job", ToPath: "/workspace/rootfs/etc/cron.d/fixture"}, false},
		{"cron_link", celengine.CELInputEvent{CreatedPath: "/etc/cron.d/evil", ExistingPath: "/tmp/job", IsSymlink: true}, true},
		{"cron_link", celengine.CELInputEvent{CreatedPath: "/workspace/rootfs/etc/cron.d/fixture", ExistingPath: "/tmp/job", IsSymlink: true}, false},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/cron.d", TargetPath: "/tmp/cron"}, true},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/cron.d/", TargetPath: "/tmp/cron"}, true},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/cron.d/evil", TargetPath: "/tmp/cron"}, true},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "/var/spool/cron", TargetPath: "/tmp/cron"}, true},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/crontab", TargetPath: "/tmp/crontab"}, true},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "/workspace/rootfs/etc/cron.d", TargetPath: "/tmp/cron"}, false},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "/tmp/source", TargetPath: "/etc/cron.d"}, false},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc", TargetPath: "/tmp/etc"}, false},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "etc/cron.d", TargetPath: "/tmp/cron"}, false},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/cron.daily-backup", TargetPath: "/tmp/cron"}, false},
		{"cron_mount_exposure", celengine.CELInputEvent{SourcePath: "/var/lib/docker/overlay2/rootfs", TargetPath: "/tmp/rootfs"}, false},
		{"cron_mount_exposure", celengine.CELInputEvent{TargetPath: "/tmp/cron"}, false},

		// Shell startup files.
		{"shell_rc_write", celengine.CELInputEvent{Path: "/home/runner/.bashrc", IsWrite: true}, true},
		{"shell_rc_write", celengine.CELInputEvent{Path: "/workspace/dotfiles/.bashrc", IsWrite: true}, true},
		{"shell_rc_write", celengine.CELInputEvent{Path: "/etc/profile.d/evil.sh", IsWrite: true}, true},
		{"shell_rc_write", celengine.CELInputEvent{Path: "/workspace/rootfs/etc/profile.d/fixture.sh", IsWrite: true}, false},
		{"shell_rc_move", celengine.CELInputEvent{FromPath: "/tmp/rc", ToPath: "/home/runner/.bashrc"}, true},
		{"shell_rc_move", celengine.CELInputEvent{FromPath: "/tmp/rc", ToPath: "/workspace/dotfiles/.bashrc"}, true},
		{"shell_rc_move", celengine.CELInputEvent{FromPath: "/tmp/rc", ToPath: "/workspace/rootfs/etc/profile.d/fixture.sh"}, false},
		{"shell_rc_link", celengine.CELInputEvent{CreatedPath: "/home/runner/.zshrc", ExistingPath: "/tmp/rc", IsSymlink: true}, true},
		{"shell_rc_link", celengine.CELInputEvent{CreatedPath: "/workspace/dotfiles/.zshrc", ExistingPath: "/tmp/rc", IsSymlink: true}, true},
		{"shell_rc_link", celengine.CELInputEvent{CreatedPath: "/workspace/rootfs/etc/profile.d/fixture.sh", ExistingPath: "/tmp/rc", IsSymlink: true}, false},
		{"shell_rc_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/profile.d", TargetPath: "/tmp/profile.d"}, true},
		{"shell_rc_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/profile.d/evil.sh", TargetPath: "/tmp/profile"}, true},
		{"shell_rc_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/profile", TargetPath: "/tmp/profile"}, true},
		{"shell_rc_mount_exposure", celengine.CELInputEvent{SourcePath: "/home/runner/.bashrc", TargetPath: "/tmp/bashrc"}, true},
		{"shell_rc_mount_exposure", celengine.CELInputEvent{SourcePath: "/workspace/rootfs/etc/profile", TargetPath: "/tmp/profile"}, false},
		{"shell_rc_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/profile.d-backup", TargetPath: "/tmp/profile"}, false},
		{"shell_rc_mount_exposure", celengine.CELInputEvent{SourcePath: "/proc/thread-self/fd/10", TargetPath: "/tmp/fd"}, false},

		// Dynamic linker preload.
		{"ld_so_preload_write", celengine.CELInputEvent{Path: "/etc/ld.so.preload", IsWrite: true}, true},
		{"ld_so_preload_write", celengine.CELInputEvent{Path: "/workspace/rootfs/etc/ld.so.conf.d/fixture.conf", IsWrite: true}, false},
		{"ld_so_preload_move", celengine.CELInputEvent{FromPath: "/tmp/p", ToPath: "/etc/ld.so.preload"}, true},
		{"ld_so_preload_move", celengine.CELInputEvent{FromPath: "/tmp/p", ToPath: "/workspace/rootfs/etc/ld.so.conf.d/fixture.conf"}, false},
		{"ld_so_preload_link", celengine.CELInputEvent{CreatedPath: "/etc/ld.so.conf.d/evil.conf", ExistingPath: "/tmp/p", IsHardlink: true}, true},
		{"ld_so_preload_link", celengine.CELInputEvent{CreatedPath: "/workspace/rootfs/etc/ld.so.conf.d/fixture.conf", ExistingPath: "/tmp/p", IsHardlink: true}, false},
		{"ld_so_preload_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/ld.so.conf.d", TargetPath: "/tmp/ld"}, true},
		{"ld_so_preload_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/ld.so.preload", TargetPath: "/tmp/preload"}, true},
		{"ld_so_preload_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/ld.so.conf", TargetPath: "/tmp/ld"}, true},
		{"ld_so_preload_mount_exposure", celengine.CELInputEvent{SourcePath: "/workspace/rootfs/etc/ld.so.preload", TargetPath: "/tmp/preload"}, false},
		{"ld_so_preload_mount_exposure", celengine.CELInputEvent{SourcePath: "/etc/ld.so.conf.d-backup", TargetPath: "/tmp/ld"}, false},
		{"ld_so_preload_mount_exposure", celengine.CELInputEvent{SourcePath: "/var/lib/docker/overlay2/rootfs", TargetPath: "/tmp/rootfs"}, false},

		// User systemd service unit (same move/link gap closed).
		{"user_systemd_service_move", celengine.CELInputEvent{FromPath: "/tmp/x.service", ToPath: "/home/runner/.config/systemd/user/x.service"}, true},
		{"user_systemd_service_link", celengine.CELInputEvent{CreatedPath: "/home/runner/.config/systemd/user/x.service", ExistingPath: "/tmp/x.service", IsSymlink: true}, true},
		{"user_systemd_service_mount_exposure", celengine.CELInputEvent{SourcePath: "/home/runner/.config/systemd/user", TargetPath: "/tmp/user-systemd"}, true},
		{"user_systemd_service_mount_exposure", celengine.CELInputEvent{SourcePath: "/home/runner/.config/systemd/user/evil.service", TargetPath: "/tmp/evil.service"}, true},
		{"user_systemd_service_mount_exposure", celengine.CELInputEvent{SourcePath: "/workspace/systemd/evil.service", TargetPath: "/tmp/evil.service"}, false},
		{"user_systemd_service_mount_exposure", celengine.CELInputEvent{SourcePath: "/var/lib/docker/overlay2/rootfs", TargetPath: "/tmp/rootfs"}, false},
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

	wantActions := map[string]rule.RuleAction{
		"cron_write":                          rule.RuleActionCollect,
		"cron_move":                           rule.RuleActionCollect,
		"cron_link":                           rule.RuleActionDetect,
		"cron_mount_exposure":                 rule.RuleActionDetect,
		"shell_rc_write":                      rule.RuleActionCollect,
		"shell_rc_move":                       rule.RuleActionCollect,
		"shell_rc_link":                       rule.RuleActionCollect,
		"shell_rc_mount_exposure":             rule.RuleActionCollect,
		"ld_so_preload_write":                 rule.RuleActionDetect,
		"ld_so_preload_move":                  rule.RuleActionDetect,
		"ld_so_preload_link":                  rule.RuleActionDetect,
		"ld_so_preload_mount_exposure":        rule.RuleActionDetect,
		"user_systemd_service_move":           rule.RuleActionDetect,
		"user_systemd_service_link":           rule.RuleActionDetect,
		"user_systemd_service_mount_exposure": rule.RuleActionDetect,
	}
	for id, want := range wantActions {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("expected rule %q to be shipped", id)
		}
		if r.Action != want {
			t.Fatalf("rule %q action=%q, want %q", id, r.Action, want)
		}
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

	for _, id := range []string{
		"cron_mount_exposure",
		"shell_rc_mount_exposure",
		"ld_so_preload_mount_exposure",
		"user_systemd_service_mount_exposure",
	} {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("expected rule %q to be shipped", id)
		}
		if r.EventType != jobevent.Mount {
			t.Fatalf("rule %q event_type=%q, want %q", id, r.EventType, jobevent.Mount)
		}
	}

	for _, pair := range []struct {
		dirs  string
		roots string
	}{
		{dirs: "cron_persistence_dirs", roots: "cron_persistence_dir_roots"},
		{dirs: "shell_rc_dirs", roots: "shell_rc_dir_roots"},
		{dirs: "ld_preload_dirs", roots: "ld_preload_dir_roots"},
	} {
		dirs := slices.Clone(set.Lists[pair.dirs])
		for i := range dirs {
			dirs[i] = strings.TrimSuffix(dirs[i], "/")
		}
		if !slices.Equal(dirs, set.Lists[pair.roots]) {
			t.Fatalf("list %q must equal %q with trailing slashes removed: got %v, want %v",
				pair.roots, pair.dirs, set.Lists[pair.roots], dirs)
		}
	}
}

func caseLabel(in celengine.CELInputEvent) string {
	switch {
	case in.SourcePath != "":
		return "source=" + in.SourcePath
	case in.ToPath != "":
		return "to=" + in.ToPath
	case in.CreatedPath != "":
		return "link=" + in.CreatedPath
	default:
		return "path=" + in.Path
	}
}
