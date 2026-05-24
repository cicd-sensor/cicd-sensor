package protoconv

import (
	"reflect"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// TestJobIdentity_RoundTrip_Shared verifies that shared -> proto -> shared
// preserves every field. The conversion is small but easy to regress on when
// a new identity field is added, so this is the load-bearing pin.
func TestJobIdentity_RoundTrip_Shared(t *testing.T) {
	tests := []struct {
		name string
		in   jobcontext.JobIdentity
	}{
		{
			name: "github identity with all fields",
			in: jobcontext.JobIdentity{
				Provider:               jobcontext.ProviderGitHub,
				ProviderHost:           "github.com",
				ProjectPath:            "acme/example",
				GitHubRunID:            "123",
				GitHubJob:              "build",
				GitHubRunAttempt:       "2",
				GitHubRunnerTrackingID: "runner-1",
			},
		},
		{
			name: "gitlab identity",
			in: jobcontext.JobIdentity{
				Provider:     jobcontext.ProviderGitLab,
				ProviderHost: "gitlab.com",
				ProjectPath:  "group/project",
				GitLabJobID:  "987654",
			},
		},
		{
			name: "zero identity round-trips to zero",
			in:   jobcontext.JobIdentity{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proto := ToProtoJobIdentity(tt.in)
			got := FromProtoJobIdentity(proto)
			if !reflect.DeepEqual(tt.in, got) {
				t.Fatalf("round-trip mismatch:\n got:  %+v\n want: %+v", got, tt.in)
			}
		})
	}
}

// TestJobIdentity_RoundTrip_Proto verifies proto -> shared -> proto also
// preserves every field (idempotent from the wire side).
func TestJobIdentity_RoundTrip_Proto(t *testing.T) {
	in := &managerv1.JobIdentity{
		Provider:               string(jobcontext.ProviderGitHub),
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GithubRunId:            "123",
		GithubJob:              "build",
		GithubRunAttempt:       "2",
		GithubRunnerTrackingId: "runner-1",
	}
	got := ToProtoJobIdentity(FromProtoJobIdentity(in))
	if in.Provider != got.Provider ||
		in.ProviderHost != got.ProviderHost ||
		in.ProjectPath != got.ProjectPath ||
		in.GithubRunId != got.GithubRunId ||
		in.GithubJob != got.GithubJob ||
		in.GithubRunAttempt != got.GithubRunAttempt ||
		in.GithubRunnerTrackingId != got.GithubRunnerTrackingId ||
		in.GitlabJobId != got.GitlabJobId {
		t.Fatalf("proto round-trip mismatch:\n got:  %+v\n want: %+v", got, in)
	}
}

func TestFromProtoJobIdentity_NilReturnsZero(t *testing.T) {
	got := FromProtoJobIdentity(nil)
	if got != (jobcontext.JobIdentity{}) {
		t.Fatalf("nil proto identity: got %+v, want zero jobcontext.JobIdentity", got)
	}
}

func TestToProtoScope(t *testing.T) {
	tests := []struct {
		name string
		in   jobcontext.ScopeType
		want managerv1.Scope
	}{
		{name: "host", in: jobcontext.ScopeTypeHost, want: managerv1.Scope_SCOPE_HOST},
		{name: "project", in: jobcontext.ScopeTypeProject, want: managerv1.Scope_SCOPE_PROJECT},
		{name: "empty", in: "", want: managerv1.Scope_SCOPE_UNSPECIFIED},
		{name: "unknown", in: jobcontext.ScopeType("other"), want: managerv1.Scope_SCOPE_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToProtoScope(tt.in); got != tt.want {
				t.Fatalf("ToProtoScope(%q): got %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestRuleSources_RoundTrip(t *testing.T) {
	collect := rule.RuleActionCollect
	maxAlerts := 3
	disable := true
	in := []rulesource.LoadedRules{{
		RuleSets: []rule.RuleSet{{
			RulesetID: "set",
			Revision:  "sha256:test",
			Lists:     map[string][]string{"bins": {"/bin/bash"}},
			Rules: []rule.Rule{{
				RuleID:    "detect_bash",
				RuleName:  "Detect bash",
				EventType: jobevent.ProcessExec,
				Tags:      map[string]string{"severity": "medium"},
				Target: rule.RuleTarget{
					Include: []rule.RuleTargetMatcher{{ProviderHost: "github.com", Path: "acme/example"}},
				},
				Condition:  `process.exec_path.endsWith("/bash")`,
				Exceptions: `process.argv.exists(a, a.contains("safe"))`,
				Action:     rule.RuleActionDetect,
				MaxAlerts:  maxAlerts,
			}},
		}},
		RuleModifiers: []rule.RuleModifier{{
			ModifierID: "mod",
			Revision:   "sha256:test",
			Targets:    []rule.RuleModifierTarget{{RulesetID: "set", RuleID: "detect_bash"}},
			AddTargetExclude: []rule.RuleTargetMatcher{
				{ProviderHost: "github.com", Path: "acme/ignored"},
			},
			AddExceptions:     `process.exec_path.endsWith("/true")`,
			OverrideAction:    &collect,
			OverrideMaxAlerts: &maxAlerts,
			Disable:           &disable,
		}},
	}}

	got := FromProtoRuleSources(ToProtoRuleSources(in))
	if len(got) != 1 || len(got[0].RuleSets) != 1 || len(got[0].RuleModifiers) != 1 {
		t.Fatalf("rule source round-trip mismatch:\n got:  %+v\n want: %+v", got, in)
	}
	gotRule := got[0].RuleSets[0].Rules[0]
	if got[0].RuleSets[0].Revision != "sha256:test" {
		t.Fatalf("ruleset revision: got %q, want sha256:test", got[0].RuleSets[0].Revision)
	}
	if gotRule.RuleID != "detect_bash" ||
		gotRule.RuleName != "Detect bash" ||
		gotRule.EventType != jobevent.ProcessExec ||
		gotRule.Condition != `process.exec_path.endsWith("/bash")` ||
		gotRule.Exceptions != `process.argv.exists(a, a.contains("safe"))` ||
		gotRule.MaxAlerts != maxAlerts ||
		gotRule.Action != rule.RuleActionDetect ||
		gotRule.Tags["severity"] != "medium" ||
		len(gotRule.Target.Include) != 1 ||
		gotRule.Target.Include[0].Path != "acme/example" {
		t.Fatalf("rule round-trip mismatch: %+v", gotRule)
	}
	gotModifier := got[0].RuleModifiers[0]
	if gotModifier.Revision != "sha256:test" {
		t.Fatalf("modifier revision: got %q, want sha256:test", gotModifier.Revision)
	}
	if gotModifier.OverrideAction == nil || *gotModifier.OverrideAction != collect {
		t.Fatalf("override_action: got %v, want %q", gotModifier.OverrideAction, collect)
	}
	if gotModifier.OverrideMaxAlerts == nil || *gotModifier.OverrideMaxAlerts != maxAlerts {
		t.Fatalf("override_max_alerts: got %v, want %d", gotModifier.OverrideMaxAlerts, maxAlerts)
	}
	if gotModifier.Disable == nil || *gotModifier.Disable != disable {
		t.Fatalf("disable: got %v, want %v", gotModifier.Disable, disable)
	}
	gotModifier.OverrideAction = nil
	gotModifier.OverrideMaxAlerts = nil
	gotModifier.Disable = nil
	wantModifier := in[0].RuleModifiers[0]
	wantModifier.OverrideAction = nil
	wantModifier.OverrideMaxAlerts = nil
	wantModifier.Disable = nil
	if gotModifier.ModifierID != wantModifier.ModifierID ||
		!reflect.DeepEqual(gotModifier.Targets, wantModifier.Targets) ||
		gotModifier.AddExceptions != wantModifier.AddExceptions ||
		!reflect.DeepEqual(gotModifier.AddTargetExclude, wantModifier.AddTargetExclude) {
		t.Fatalf("modifier round-trip mismatch:\n got:  %+v\n want: %+v", gotModifier, wantModifier)
	}
}

func TestRuleSources_NilProtoElements(t *testing.T) {
	got := FromProtoRuleSources([]*managerv1.RuleSource{
		nil,
		{
			RuleSets: []*managerv1.RuleSet{
				nil,
				{
					RulesetId: "set",
					Lists: map[string]*managerv1.StringList{
						"nil_list": nil,
					},
					Rules: []*managerv1.Rule{
						nil,
						{
							RuleId:    "detect_bash",
							EventType: string(jobevent.ProcessExec),
							Target: &managerv1.RuleTarget{
								Include: []*managerv1.RuleTargetMatcher{nil, {Path: "acme/example"}},
							},
							Condition: `process.exec_path.endsWith("/bash")`,
							Action:    string(rule.RuleActionDetect),
						},
					},
				},
			},
			RuleModifiers: []*managerv1.RuleModifier{
				nil,
				{
					ModifierId: "mod",
					Targets: []*managerv1.RuleModifierTarget{
						nil,
						{RulesetId: "set", RuleId: "detect_bash"},
					},
					AddTargetExclude: []*managerv1.RuleTargetMatcher{nil, {Path: "acme/ignored"}},
				},
			},
		},
	})

	if len(got) != 2 {
		t.Fatalf("rule sources len: got %d, want 2", len(got))
	}
	if len(got[0].RuleSets) != 0 || len(got[0].RuleModifiers) != 0 {
		t.Fatalf("nil rule source should become empty LoadedRules: %+v", got[0])
	}

	source := got[1]
	if len(source.RuleSets) != 2 {
		t.Fatalf("rule sets len: got %d, want 2", len(source.RuleSets))
	}
	if !reflect.DeepEqual(source.RuleSets[0], rule.RuleSet{}) {
		t.Fatalf("nil rule set should become zero value: %+v", source.RuleSets[0])
	}
	if values, ok := source.RuleSets[1].Lists["nil_list"]; !ok || values != nil {
		t.Fatalf("nil proto StringList should become nil value slice: %#v", source.RuleSets[1].Lists)
	}
	if len(source.RuleSets[1].Rules) != 2 || !reflect.DeepEqual(source.RuleSets[1].Rules[0], rule.Rule{}) {
		t.Fatalf("nil rule should become zero value: %+v", source.RuleSets[1].Rules)
	}
	if len(source.RuleSets[1].Rules[1].Target.Include) != 2 ||
		source.RuleSets[1].Rules[1].Target.Include[0] != (rule.RuleTargetMatcher{}) ||
		source.RuleSets[1].Rules[1].Target.Include[1].Path != "acme/example" {
		t.Fatalf("target matchers mismatch: %+v", source.RuleSets[1].Rules[1].Target.Include)
	}

	if len(source.RuleModifiers) != 2 || !reflect.DeepEqual(source.RuleModifiers[0], rule.RuleModifier{}) {
		t.Fatalf("nil modifier should become zero value: %+v", source.RuleModifiers)
	}
	if len(source.RuleModifiers[1].Targets) != 2 ||
		source.RuleModifiers[1].Targets[0] != (rule.RuleModifierTarget{}) ||
		source.RuleModifiers[1].Targets[1].RuleID != "detect_bash" {
		t.Fatalf("modifier targets mismatch: %+v", source.RuleModifiers[1].Targets)
	}
	if len(source.RuleModifiers[1].AddTargetExclude) != 2 ||
		source.RuleModifiers[1].AddTargetExclude[0] != (rule.RuleTargetMatcher{}) ||
		source.RuleModifiers[1].AddTargetExclude[1].Path != "acme/ignored" {
		t.Fatalf("modifier target excludes mismatch: %+v", source.RuleModifiers[1].AddTargetExclude)
	}
}

func TestRuleSources_ConversionDoesNotAliasMaps(t *testing.T) {
	in := []rulesource.LoadedRules{{
		RuleSets: []rule.RuleSet{{
			RulesetID: "set",
			Lists:     map[string][]string{"bins": {"/bin/bash"}},
			Rules: []rule.Rule{{
				RuleID:    "detect_bash",
				EventType: jobevent.ProcessExec,
				Condition: `process.exec_path.endsWith("/bash")`,
				Action:    rule.RuleActionDetect,
				Tags:      map[string]string{"severity": "medium"},
			}},
		}},
	}}

	proto := ToProtoRuleSources(in)
	proto[0].RuleSets[0].Lists["bins"].Values[0] = "/bin/zsh"
	proto[0].RuleSets[0].Rules[0].Tags["severity"] = "high"
	if got := in[0].RuleSets[0].Lists["bins"][0]; got != "/bin/bash" {
		t.Fatalf("proto lists aliased source: got %q", got)
	}
	if got := in[0].RuleSets[0].Rules[0].Tags["severity"]; got != "medium" {
		t.Fatalf("proto tags aliased source: got %q", got)
	}

	got := FromProtoRuleSources(proto)
	got[0].RuleSets[0].Lists["bins"][0] = "/bin/fish"
	got[0].RuleSets[0].Rules[0].Tags["severity"] = "critical"
	if got := proto[0].RuleSets[0].Lists["bins"].Values[0]; got != "/bin/zsh" {
		t.Fatalf("source lists aliased proto: got %q", got)
	}
	if got := proto[0].RuleSets[0].Rules[0].Tags["severity"]; got != "high" {
		t.Fatalf("source tags aliased proto: got %q", got)
	}
}
