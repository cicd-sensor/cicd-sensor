package jobregistry

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestBuildHostScopeFromManagerConfigSkipsDirectBaseline(t *testing.T) {
	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}
	jr.SetBaselineLoadForTesting(func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		t.Fatal("baseline loader should not be called when manager config is present")
		return rulesource.LoadedRules{}, nil
	})

	scope, err := jr.buildHostScopeFromManagerConfig(testCtx, id, meta, "machine", managerclient.Connection{}, fakeManagerFetcher{})
	if err != nil {
		t.Fatalf("buildHostScopeFromManagerConfig: %v", err)
	}
	if got := len(scope.RuleSets); got != 0 {
		t.Fatalf("rule_sets: got %d, want 0", got)
	}
}
