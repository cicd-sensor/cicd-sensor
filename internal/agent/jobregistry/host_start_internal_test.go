package jobregistry

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestBuildHostScopeFromBaseline(t *testing.T) {
	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")
	baselineCalled := false
	restoreBaselineLoad := baselineLoad
	baselineLoad = func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		baselineCalled = true
		return rulesource.LoadedRules{RuleSets: []rule.RuleSet{{
			RulesetID: "baseline",
			Rules: []rule.Rule{{
				RuleID:    "detect_bash",
				EventKind: jobevent.ProcessExec,
				Condition: `process_name == "bash"`,
				Action:    rule.RuleActionDetect,
			}},
		}}}, nil
	}
	t.Cleanup(func() { baselineLoad = restoreBaselineLoad })

	scope, err := jr.buildHostScopeFromBaseline(testCtx, id)
	if err != nil {
		t.Fatalf("buildHostScopeFromBaseline: %v", err)
	}
	if !baselineCalled {
		t.Fatal("baseline loader was not called")
	}
	if got := len(scope.RuleSets); got != 1 {
		t.Fatalf("rule_sets: got %d, want 1", got)
	}
	if got := len(scope.ResolvedRules.Rules); got != 1 {
		t.Fatalf("resolved rules: got %d, want 1", got)
	}
}

func TestBuildHostScopeFromManagerConfigSkipsDirectBaseline(t *testing.T) {
	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}
	restoreBaselineLoad := baselineLoad
	baselineLoad = func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		t.Fatal("baseline loader should not be called when manager config is present")
		return rulesource.LoadedRules{}, nil
	}
	t.Cleanup(func() { baselineLoad = restoreBaselineLoad })

	scope, err := jr.buildHostScopeFromManagerConfig(testCtx, id, meta, "machine", managerclient.Connection{}, fakeManagerFetcher{})
	if err != nil {
		t.Fatalf("buildHostScopeFromManagerConfig: %v", err)
	}
	if got := len(scope.RuleSets); got != 0 {
		t.Fatalf("rule_sets: got %d, want 0", got)
	}
}

func TestBuildHostScopeFromBaselineFailureFailsClosed(t *testing.T) {
	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")
	wantErr := errors.New("baseline unavailable")
	restoreBaselineLoad := baselineLoad
	baselineLoad = func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		return rulesource.LoadedRules{}, wantErr
	}
	t.Cleanup(func() { baselineLoad = restoreBaselineLoad })

	_, err := jr.buildHostScopeFromBaseline(testCtx, id)
	if !errors.Is(err, wantErr) {
		t.Fatalf("buildHostScopeFromBaseline error: got %v, want %v", err, wantErr)
	}
}
