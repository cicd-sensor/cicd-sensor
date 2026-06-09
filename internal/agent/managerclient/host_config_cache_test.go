package managerclient

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestHostConfigCache_FetchConfig(t *testing.T) {
	req := testFetchConfigRequest()

	tests := []struct {
		name    string
		prime   bool
		wantErr error
	}{
		{
			name:    "error before prime",
			wantErr: ErrConfigCacheNotReady,
		},
		{
			name:  "returns cached config after prime",
			prime: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache, err := NewHostConfigCache(slog.Default(), &sequenceFetcher{
				results: []*FetchResult{{ConfigRevision: "rev-1"}},
			}, req, time.Hour)
			if err != nil {
				t.Fatalf("NewHostConfigCache: %v", err)
			}
			if tc.prime {
				if err := cache.Prime(t.Context()); err != nil {
					t.Fatalf("Prime: %v", err)
				}
			}

			got, err := cache.FetchConfig(t.Context(), req)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("FetchConfig error: got %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FetchConfig: %v", err)
			}
			if got.ConfigRevision != "rev-1" {
				t.Fatalf("config_revision: got %q, want rev-1", got.ConfigRevision)
			}
		})
	}
}

func TestHostConfigCache_FetchConfigClonesCachedResult(t *testing.T) {
	req := testFetchConfigRequest()
	cache, err := NewHostConfigCache(slog.Default(), &sequenceFetcher{
		results: []*FetchResult{{
			ConfigRevision: "rev-1",
			OutputSettings: &managerv1beta1.OutputSettings{
				Summary: &managerv1beta1.OutputSetting{Enabled: true},
			},
		}},
	}, req, time.Hour)
	if err != nil {
		t.Fatalf("NewHostConfigCache: %v", err)
	}
	if err := cache.Prime(t.Context()); err != nil {
		t.Fatalf("Prime: %v", err)
	}

	first, err := cache.FetchConfig(t.Context(), req)
	if err != nil {
		t.Fatalf("FetchConfig first: %v", err)
	}
	first.OutputSettings.Summary.Enabled = false

	second, err := cache.FetchConfig(t.Context(), req)
	if err != nil {
		t.Fatalf("FetchConfig second: %v", err)
	}
	if !second.OutputSettings.GetSummary().GetEnabled() {
		t.Fatal("cached output settings were mutated by caller")
	}
}

func TestHostConfigCache_FetchConfigClonesRuleSources(t *testing.T) {
	req := testFetchConfigRequest()
	cache, err := NewHostConfigCache(slog.Default(), &sequenceFetcher{
		results: []*FetchResult{{
			ConfigRevision: "rev-1",
			RuleSources: []rulesource.LoadedRules{{
				RuleSets: []rule.RuleSet{{
					RulesetID: "managed",
					Lists:     map[string][]string{"paths": {"/safe"}},
					Rules: []rule.Rule{{
						RuleID:    "rule-1",
						EventType: jobevent.ProcessExec,
						Condition: `process.exec_path.endsWith("/bash")`,
						Action:    rule.RuleActionDetect,
						Target: rule.RuleTarget{
							Exclude: []rule.RuleTargetMatcher{{Path: "acme/safe"}},
						},
						Tags: map[string]string{"source": "manager"},
					}},
				}},
				RuleModifiers: []rule.RuleModifier{{
					ModifierID:       "mod-1",
					Targets:          []rule.RuleModifierTarget{{RulesetID: "managed", RuleID: "rule-1"}},
					AddTargetExclude: []rule.RuleTargetMatcher{{Path: "acme/skip"}},
				}},
			}},
		}},
	}, req, time.Hour)
	if err != nil {
		t.Fatalf("NewHostConfigCache: %v", err)
	}
	if err := cache.Prime(t.Context()); err != nil {
		t.Fatalf("Prime: %v", err)
	}

	first, err := cache.FetchConfig(t.Context(), req)
	if err != nil {
		t.Fatalf("FetchConfig first: %v", err)
	}
	first.RuleSources[0].RuleSets[0].Lists["paths"][0] = "/mutated"
	first.RuleSources[0].RuleSets[0].Rules[0].Target.Exclude[0].Path = "mutated/project"
	first.RuleSources[0].RuleSets[0].Rules[0].Target.Exclude = append(
		first.RuleSources[0].RuleSets[0].Rules[0].Target.Exclude,
		rule.RuleTargetMatcher{Path: "mutated/append"},
	)
	first.RuleSources[0].RuleSets[0].Rules[0].Tags["source"] = "mutated"
	first.RuleSources[0].RuleModifiers[0].AddTargetExclude[0].Path = "mutated/skip"
	first.RuleSources[0].RuleModifiers[0].AddTargetExclude = append(
		first.RuleSources[0].RuleModifiers[0].AddTargetExclude,
		rule.RuleTargetMatcher{Path: "mutated/modifier-append"},
	)

	second, err := cache.FetchConfig(t.Context(), req)
	if err != nil {
		t.Fatalf("FetchConfig second: %v", err)
	}
	if got := second.RuleSources[0].RuleSets[0].Lists["paths"][0]; got != "/safe" {
		t.Fatalf("rule list mutation leaked: got %q, want /safe", got)
	}
	if got := second.RuleSources[0].RuleSets[0].Rules[0].Target.Exclude[0].Path; got != "acme/safe" {
		t.Fatalf("rule target mutation leaked: got %q, want acme/safe", got)
	}
	if got := len(second.RuleSources[0].RuleSets[0].Rules[0].Target.Exclude); got != 1 {
		t.Fatalf("rule target append leaked: got len %d, want 1", got)
	}
	if got := second.RuleSources[0].RuleSets[0].Rules[0].Tags["source"]; got != "manager" {
		t.Fatalf("rule tags mutation leaked: got %q, want manager", got)
	}
	if got := second.RuleSources[0].RuleModifiers[0].AddTargetExclude[0].Path; got != "acme/skip" {
		t.Fatalf("rule modifier mutation leaked: got %q, want acme/skip", got)
	}
	if got := len(second.RuleSources[0].RuleModifiers[0].AddTargetExclude); got != 1 {
		t.Fatalf("rule modifier append leaked: got len %d, want 1", got)
	}
}

func TestHostConfigCache_RunRefreshesAndKeepsLastKnownGood(t *testing.T) {
	req := testFetchConfigRequest()
	fetcher := &sequenceFetcher{
		results: []*FetchResult{
			{ConfigRevision: "rev-1"},
			{ConfigRevision: "rev-2"},
		},
		errs: []error{errors.New("manager unavailable")},
	}
	cache, err := NewHostConfigCache(slog.Default(), fetcher, req, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewHostConfigCache: %v", err)
	}
	if err := cache.Prime(t.Context()); err != nil {
		t.Fatalf("Prime: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go cache.Run(ctx)

	waitForFetchCount(t, fetcher, 2)
	waitForCachedRevision(t, cache, req, "rev-2")

	waitForFetchCount(t, fetcher, 3)
	got, err := cache.FetchConfig(t.Context(), req)
	if err != nil {
		t.Fatalf("FetchConfig after failed refresh: %v", err)
	}
	if got.ConfigRevision != "rev-2" {
		t.Fatalf("config_revision after failed refresh: got %q, want rev-2", got.ConfigRevision)
	}
}

func waitForCachedRevision(t *testing.T, cache *HostConfigCache, req *managerv1beta1.FetchConfigRequest, want string) {
	t.Helper()
	deadline := time.After(500 * time.Millisecond)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		got, err := cache.FetchConfig(t.Context(), req)
		if err != nil {
			t.Fatalf("FetchConfig while waiting for revision: %v", err)
		}
		if got.ConfigRevision == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("config_revision: still not %q before timeout", want)
		case <-ticker.C:
		}
	}
}

func testFetchConfigRequest() *managerv1beta1.FetchConfigRequest {
	return &managerv1beta1.FetchConfigRequest{
		RunnerType: "kubernetes",
		JobIdentity: &managerv1beta1.JobIdentity{
			Provider:               "github",
			ProviderHost:           "github.com",
			ProjectPath:            "cicd-sensor/host-config",
			GithubRunId:            "1",
			GithubJob:              "host-config",
			GithubRunAttempt:       "1",
			GithubRunnerTrackingId: "host-config",
		},
	}
}

func waitForFetchCount(t *testing.T, fetcher *sequenceFetcher, want int) {
	t.Helper()
	deadline := time.After(500 * time.Millisecond)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if fetcher.callCount() >= want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("fetch count: got %d, want at least %d", fetcher.callCount(), want)
		case <-ticker.C:
		}
	}
}

type sequenceFetcher struct {
	mu      sync.Mutex
	results []*FetchResult
	errs    []error
	calls   int
}

func (f *sequenceFetcher) FetchConfig(context.Context, *managerv1beta1.FetchConfigRequest) (*FetchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if len(f.results) > 0 {
		result := f.results[0]
		f.results = f.results[1:]
		return result, nil
	}
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return nil, err
	}
	return nil, errors.New("unexpected fetch")
}

func (f *sequenceFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}
