package baseline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

const testRuleBundleA = `rule_sets:
  - ruleset_id: test-rule-a
    rules:
      - rule_id: test_rule_a
        description: test
        event_type: file_open
        condition: 'is_read'
        action: detect
`

const testRuleBundleB = `rule_sets:
  - ruleset_id: test-rule-b
    rules:
      - rule_id: test_rule_b
        description: test
        event_type: file_open
        condition: 'is_read'
        action: detect
`

const testRegistryAddr = "127.0.0.1:0"
const testBaselineVersion = "v20260618-001"

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type testRegistry struct {
	server *httptest.Server
	repo   string
	tag    string

	mu          sync.Mutex
	pullCounter atomic.Int32
}

func newTestRegistry(t *testing.T, addr string) *testRegistry {
	t.Helper()
	tr := &testRegistry{repo: "test/rules", tag: "latest"}
	reg := registry.New()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("tcp listen on %s is not permitted in this test environment: %v", addr, err)
		}
		t.Fatalf("listen test registry on %s: %v", addr, err)
	}
	tr.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/sha256:") {
			tr.pullCounter.Add(1)
		}
		reg.ServeHTTP(w, r)
	}))
	tr.server.Listener = ln
	tr.server.Start()
	t.Cleanup(tr.server.Close)
	return tr
}

func (tr *testRegistry) ref(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(tr.server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return u.Host + "/" + tr.repo + ":" + tr.tag
}

func (tr *testRegistry) source(t *testing.T, name string) source {
	t.Helper()
	return source{name: name, ref: tr.ref(t)}
}

func (tr *testRegistry) publish(t *testing.T, bundleYAML string) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()

	layer := static.NewLayer(gzipBytes(t, bundleYAML), types.OCILayer)
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: layer,
	})
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.Annotations(img, map[string]string{
		ociVersionAnnotation: testBaselineVersion,
	}).(v1.Image)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)

	ref, err := name.ParseReference(tr.ref(t))
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

func TestCache_FreshReturnsCached(t *testing.T) {
	want := rulesource.LoadedRules{RuleSets: mustRuleSets("r1")}
	c := &Cache{
		ttl:     time.Hour,
		ref:     "registry.invalid/x:y",
		rules:   want,
		digest:  "sha256:deadbeef",
		fetched: time.Now(),
	}

	got, err := c.get(context.Background(), newTestLogger(), []source{{name: "test", ref: c.ref}})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !sameLoadedRules(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestCache_FirstGetTriggersPull(t *testing.T) {
	tr := newTestRegistry(t, testRegistryAddr)
	tr.publish(t, testRuleBundleA)

	c := &Cache{ttl: time.Hour}

	loaded, err := c.get(context.Background(), newTestLogger(), []source{tr.source(t, "primary")})
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if len(loaded.RuleSets) != 1 || loaded.RuleSets[0].RulesetID != "test-rule-a" {
		t.Fatalf("first rules: %+v", loaded.RuleSets)
	}
	if loaded.RuleSets[0].Revision != testBaselineVersion {
		t.Fatalf("ruleset revision: got %q want %q", loaded.RuleSets[0].Revision, testBaselineVersion)
	}
	if got := tr.pullCounter.Load(); got != 1 {
		t.Fatalf("registry layer pulls: got %d, want 1", got)
	}
	if c.digest == "" || c.ref == "" {
		t.Fatal("cache digest/ref should be set after first pull")
	}
}

func TestCache_StaleSameDigestReusesCache(t *testing.T) {
	tr := newTestRegistry(t, testRegistryAddr)
	tr.publish(t, testRuleBundleA)

	c := &Cache{ttl: 10 * time.Millisecond}

	if _, err := c.get(context.Background(), newTestLogger(), []source{tr.source(t, "primary")}); err != nil {
		t.Fatalf("first get: %v", err)
	}
	digestBefore := c.digest
	if got := tr.pullCounter.Load(); got != 1 {
		t.Fatalf("layer pulls after first: got %d, want 1", got)
	}

	time.Sleep(20 * time.Millisecond)

	loaded, err := c.get(context.Background(), newTestLogger(), []source{tr.source(t, "primary")})
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if len(loaded.RuleSets) != 1 || loaded.RuleSets[0].RulesetID != "test-rule-a" {
		t.Fatalf("second rules: %+v", loaded.RuleSets)
	}
	if c.digest != digestBefore {
		t.Fatalf("digest changed unexpectedly: before=%q after=%q", digestBefore, c.digest)
	}
	if got := tr.pullCounter.Load(); got != 1 {
		t.Fatalf("layer pulls after stale unchanged: got %d, want 1", got)
	}
}

func TestCache_StaleDigestChangedTriggersRePull(t *testing.T) {
	tr := newTestRegistry(t, testRegistryAddr)
	tr.publish(t, testRuleBundleA)

	c := &Cache{ttl: 10 * time.Millisecond}

	if _, err := c.get(context.Background(), newTestLogger(), []source{tr.source(t, "primary")}); err != nil {
		t.Fatalf("first get: %v", err)
	}
	digestBefore := c.digest

	tr.publish(t, testRuleBundleB)
	time.Sleep(20 * time.Millisecond)

	loaded, err := c.get(context.Background(), newTestLogger(), []source{tr.source(t, "primary")})
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if len(loaded.RuleSets) != 1 || loaded.RuleSets[0].RulesetID != "test-rule-b" {
		t.Fatalf("second rules should reflect new content: %+v", loaded.RuleSets)
	}
	if c.digest == digestBefore {
		t.Fatal("digest should have changed after republish")
	}
	if got := tr.pullCounter.Load(); got != 2 {
		t.Fatalf("layer pulls: got %d, want 2 (initial + re-pull)", got)
	}
}

func TestCache_PullFailurePreservesCache(t *testing.T) {
	tr := newTestRegistry(t, testRegistryAddr)
	tr.publish(t, testRuleBundleA)

	c := &Cache{ttl: 10 * time.Millisecond}

	if _, err := c.get(context.Background(), newTestLogger(), []source{tr.source(t, "primary")}); err != nil {
		t.Fatalf("first get: %v", err)
	}
	rulesBefore := c.rules
	digestBefore := c.digest
	fetchedBefore := c.fetched

	tr.server.Close()
	time.Sleep(20 * time.Millisecond)

	if _, err := c.get(context.Background(), newTestLogger(), []source{tr.source(t, "primary")}); err == nil {
		t.Fatal("expected error after server close")
	}

	if !sameLoadedRules(c.rules, rulesBefore) {
		t.Fatalf("cached rules mutated on failure: before=%+v after=%+v", rulesBefore, c.rules)
	}
	if c.digest != digestBefore {
		t.Fatalf("digest mutated on failure: before=%q after=%q", digestBefore, c.digest)
	}
	if !c.fetched.Equal(fetchedBefore) {
		t.Fatalf("fetched timestamp advanced on failure: before=%v after=%v", fetchedBefore, c.fetched)
	}
}

func TestCache_ConcurrentCallersTriggerSingleLoad(t *testing.T) {
	tr := newTestRegistry(t, testRegistryAddr)
	tr.publish(t, testRuleBundleA)

	c := &Cache{ttl: time.Hour}

	const N = 8
	var wg sync.WaitGroup
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			if _, err := c.get(context.Background(), newTestLogger(), []source{tr.source(t, "primary")}); err != nil {
				t.Errorf("concurrent get: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := tr.pullCounter.Load(); got != 1 {
		t.Fatalf("layer pulls under contention: got %d, want 1", got)
	}
}

func TestCache_FallbackUsesSecondSource(t *testing.T) {
	good := newTestRegistry(t, testRegistryAddr)
	good.publish(t, testRuleBundleA)

	c := &Cache{ttl: time.Hour}
	loaded, err := c.get(context.Background(), newTestLogger(), []source{
		{name: "bad", ref: "127.0.0.1:1/missing/rules:latest"},
		good.source(t, "good"),
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(loaded.RuleSets) != 1 || loaded.RuleSets[0].RulesetID != "test-rule-a" {
		t.Fatalf("rules: %+v", loaded.RuleSets)
	}
	if c.ref != good.ref(t) {
		t.Fatalf("cached ref: got %q want %q", c.ref, good.ref(t))
	}
	if got := good.pullCounter.Load(); got != 1 {
		t.Fatalf("fallback source pulls: got %d want 1", got)
	}
}

func TestCache_FirstSourceRetriesBeforeFallback(t *testing.T) {
	restoreDelay := sourcePullRetryDelay
	sourcePullRetryDelay = time.Nanosecond
	t.Cleanup(func() { sourcePullRetryDelay = restoreDelay })

	good := newTestRegistry(t, testRegistryAddr)
	good.publish(t, testRuleBundleA)

	c := &Cache{ttl: time.Hour}
	_, err := c.get(context.Background(), newTestLogger(), []source{
		{name: "bad", ref: "127.0.0.1:1/missing/rules:latest"},
		good.source(t, "good"),
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := good.pullCounter.Load(); got != 1 {
		t.Fatalf("good source pulls: got %d want 1", got)
	}
}

func TestCache_StaleRefreshUsesProviderFirstSource(t *testing.T) {
	github := newTestRegistry(t, testRegistryAddr)
	github.publish(t, testRuleBundleA)
	gitlab := newTestRegistry(t, testRegistryAddr)
	gitlab.publish(t, testRuleBundleB)

	c := &Cache{ttl: 10 * time.Millisecond}
	if _, err := c.get(context.Background(), newTestLogger(), []source{github.source(t, "github")}); err != nil {
		t.Fatalf("initial get: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	loaded, err := c.get(context.Background(), newTestLogger(), []source{
		gitlab.source(t, "gitlab"),
		github.source(t, "github"),
	})
	if err != nil {
		t.Fatalf("provider refresh: %v", err)
	}
	if len(loaded.RuleSets) != 1 || loaded.RuleSets[0].RulesetID != "test-rule-b" {
		t.Fatalf("provider refresh should use gitlab-first source: %+v", loaded.RuleSets)
	}
	if c.ref != gitlab.ref(t) {
		t.Fatalf("cached ref: got %q want %q", c.ref, gitlab.ref(t))
	}
}

func TestCache_AllSourcesFail(t *testing.T) {
	restoreDelay := sourcePullRetryDelay
	sourcePullRetryDelay = time.Nanosecond
	t.Cleanup(func() { sourcePullRetryDelay = restoreDelay })

	c := &Cache{ttl: time.Hour}
	_, err := c.get(context.Background(), newTestLogger(), []source{
		{name: "bad-a", ref: "127.0.0.1:1/missing/rules:latest"},
		{name: "bad-b", ref: "127.0.0.1:2/missing/rules:latest"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "bad-a") || !strings.Contains(err.Error(), "bad-b") {
		t.Fatalf("joined error should include both source names: %v", err)
	}
	if !strings.Contains(err.Error(), "attempt 1") || !strings.Contains(err.Error(), "attempt 2") {
		t.Fatalf("joined error should include both retry attempts: %v", err)
	}
}

func TestSourcesForProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantRefs []string
	}{
		{name: "github", provider: "github", wantRefs: []string{GitHubOCIRef, QuayOCIRef, GitLabOCIRef}},
		{name: "gitlab", provider: "gitlab", wantRefs: []string{GitLabOCIRef, QuayOCIRef, GitHubOCIRef}},
		{name: "default", provider: "", wantRefs: []string{GitHubOCIRef, QuayOCIRef, GitLabOCIRef}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sourcesForProvider(tt.provider)
			if len(got) != len(tt.wantRefs) {
				t.Fatalf("sources: got %d want %d", len(got), len(tt.wantRefs))
			}
			for i := range got {
				if got[i].ref != tt.wantRefs[i] {
					t.Fatalf("source[%d]: got %q want %q", i, got[i].ref, tt.wantRefs[i])
				}
			}
		})
	}
}

func mustRuleSets(ids ...string) []rule.RuleSet {
	out := make([]rule.RuleSet, 0, len(ids))
	for _, id := range ids {
		out = append(out, rule.RuleSet{RulesetID: id})
	}
	return out
}

func sameLoadedRules(a, b rulesource.LoadedRules) bool {
	if len(a.RuleSets) != len(b.RuleSets) || len(a.RuleModifiers) != len(b.RuleModifiers) {
		return false
	}
	for i := range a.RuleSets {
		if a.RuleSets[i].RulesetID != b.RuleSets[i].RulesetID {
			return false
		}
	}
	for i := range a.RuleModifiers {
		if a.RuleModifiers[i].ModifierID != b.RuleModifiers[i].ModifierID {
			return false
		}
	}
	return true
}
