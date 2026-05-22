//go:build ociintegration

package baseline

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
	cosign "github.com/sigstore/cosign/v3/pkg/cosign"
)

func TestLoadFromOCI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, tt := range baselineOCIIntegrationSources() {
		t.Run(tt.name, func(t *testing.T) {
			loaded, _, err := pull(ctx, tt.ref, testLogger())
			if err != nil {
				t.Fatalf("pull %s: %v", tt.ref, err)
			}
			assertLoadedBaselineRules(t, tt.name, loaded)
		})
	}
}

func TestLoadFromOCIWithSignatureVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	withBaselineSignatureHooks(t, cosign.TrustedRoot, verifyBaselineCosignBundle)

	for _, tt := range baselineOCIIntegrationSources() {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))

			loaded, _, err := pull(ctx, tt.ref, logger)
			if err != nil {
				t.Fatalf("pull %s: %v", tt.ref, err)
			}
			assertLoadedBaselineRules(t, tt.name, loaded)
			if strings.Contains(logs.String(), baselineSignatureVerificationWarning) {
				t.Fatalf("signature verification warning for %s:\n%s", tt.ref, logs.String())
			}
		})
	}
}

func baselineOCIIntegrationSources() []source {
	if refs := strings.Fields(os.Getenv("BASELINE_OCI_REFS")); len(refs) > 0 {
		sources := make([]source, 0, len(refs))
		for i, ref := range refs {
			sources = append(sources, source{name: "env-" + strconv.Itoa(i+1), ref: ref})
		}
		return sources
	}

	return []source{
		{name: "quay", ref: QuayOCIRef},
		{name: "gitlab", ref: GitLabOCIRef},
		{name: "github", ref: GitHubOCIRef},
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
