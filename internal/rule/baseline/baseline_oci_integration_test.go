//go:build ociintegration

package baseline

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestLoadFromOCI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if refs := strings.Fields(os.Getenv("BASELINE_OCI_REFS")); len(refs) > 0 {
		sources := make([]source, 0, len(refs))
		for _, ref := range refs {
			sources = append(sources, source{name: "env", ref: ref})
		}
		testCache := &Cache{ttl: defaultCacheTTL}
		loaded, err := testCache.get(ctx, testLogger(), sources)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		assertLoadedBaselineRules(t, "env refs", loaded)
		return
	}

	tests := []struct {
		name string
		ref  string
	}{
		{name: "quay", ref: QuayOCIRef},
		{name: "gitlab", ref: GitLabOCIRef},
		// GitHub is private for now. Enable this when ghcr.io/rung/rules is
		// public or the integration environment provides registry auth.
		// {name: "github", ref: GitHubOCIRef},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loaded, _, err := pull(ctx, tt.ref, testLogger())
			if err != nil {
				t.Fatalf("pull %s: %v", tt.ref, err)
			}
			assertLoadedBaselineRules(t, tt.name, loaded)
		})
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func assertLoadedBaselineRules(t *testing.T, name string, loaded rulesource.LoadedRules) {
	t.Helper()

	if len(loaded.RuleSets) < 2 {
		t.Fatalf("%s rule_sets: got %d, want at least 2", name, len(loaded.RuleSets))
	}
	for _, set := range loaded.RuleSets {
		if set.Revision == "" {
			t.Fatalf("%s ruleset %q has empty revision", name, set.RulesetID)
		}
	}
}
