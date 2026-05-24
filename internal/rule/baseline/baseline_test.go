package baseline

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	cosign "github.com/sigstore/cosign/v3/pkg/cosign"
	cosignoci "github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const validBaselineBundleYAML = `rule_sets:
  - ruleset_id: sample-smoke-proc-environ
    rules:
      - rule_id: proc_environ_read
        description: Detect reads of /proc/<pid>/environ.
        event_type: file_open
        condition: is_read && path.startsWith("/proc/") && path.endsWith("/environ")
        action: detect
---
rule_modifiers:
  - modifier_id: sample-smoke-proc-environ-target
    targets:
      - ruleset_id: sample-smoke-proc-environ
        rule_id: proc_environ_read
    add_target_include:
      - provider_host: github.com
        path: acme/example
`

func TestMain(m *testing.M) {
	loadBaselineTrustedRoot = sync.OnceValues(testTrustedRoot(nil))
	verifyBaselineSignatureBundle = func(context.Context, name.Reference, *cosign.CheckOpts) ([]cosignoci.Signature, bool, error) {
		return nil, true, nil
	}
	os.Exit(m.Run())
}

func TestBaselineSignatureCheckOptsLocksExpectedPolicy(t *testing.T) {
	opts := baselineSignatureCheckOpts(&root.BaseTrustedMaterial{})
	if opts.TrustedMaterial == nil {
		t.Fatal("TrustedMaterial should be set")
	}
	if len(opts.RegistryClientOpts) == 0 {
		t.Fatal("RegistryClientOpts should force anonymous public baseline registry access")
	}
	if !opts.Offline {
		t.Fatal("Offline should be true")
	}
	if opts.ClaimVerifier == nil {
		t.Fatal("ClaimVerifier should be set")
	}
	if len(opts.Identities) != 1 || opts.Identities[0].Issuer != baselineSignatureExpectedIssuer || opts.Identities[0].SubjectRegExp != baselineSignatureExpectedSubject {
		t.Fatalf("identity: got %+v want issuer %q subject %q", opts.Identities, baselineSignatureExpectedIssuer, baselineSignatureExpectedSubject)
	}
	if opts.CertGithubWorkflowRepository != baselineSignatureExpectedRepository {
		t.Fatalf("repository: got %q want %q", opts.CertGithubWorkflowRepository, baselineSignatureExpectedRepository)
	}
	if opts.CertGithubWorkflowRef != baselineSignatureExpectedRef {
		t.Fatalf("ref: got %q want %q", opts.CertGithubWorkflowRef, baselineSignatureExpectedRef)
	}
	if !opts.NewBundleFormat {
		t.Fatal("NewBundleFormat should be true for cosign v3 bundle verification")
	}
}

func TestVerifyBaselineSignatureSuccessDoesNotWarn(t *testing.T) {
	ref := mustParseReference(t, "example.com/acme/rules:v1")
	var calls int
	withBaselineSignatureHooks(t,
		testTrustedRoot(nil),
		func(_ context.Context, got name.Reference, co *cosign.CheckOpts) ([]cosignoci.Signature, bool, error) {
			calls++
			if got.Name() != "example.com/acme/rules@"+testDigest() {
				t.Fatalf("verified ref: got %q", got.Name())
			}
			if !co.Offline || co.CertGithubWorkflowRepository != baselineSignatureExpectedRepository || co.CertGithubWorkflowRef != baselineSignatureExpectedRef {
				t.Fatalf("unexpected check opts: %+v", co)
			}
			return nil, true, nil
		},
	)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	verifyBaselineSignature(context.Background(), logger, "example.com/acme/rules:v1", ref, testDigest())

	if calls != 1 {
		t.Fatalf("verify calls: got %d want 1", calls)
	}
	if strings.Contains(buf.String(), baselineSignatureVerificationWarning) {
		t.Fatalf("unexpected warning log: %s", buf.String())
	}
}

func TestVerifyBaselineSignatureFailureWarnsAndContinues(t *testing.T) {
	ref := mustParseReference(t, "example.com/acme/rules:v1")
	withBaselineSignatureHooks(t,
		testTrustedRoot(nil),
		func(context.Context, name.Reference, *cosign.CheckOpts) ([]cosignoci.Signature, bool, error) {
			return nil, false, errors.New("bad signature")
		},
	)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	verifyBaselineSignature(context.Background(), logger, "example.com/acme/rules:v1", ref, testDigest())

	logOutput := buf.String()
	for _, want := range []string{
		baselineSignatureVerificationWarning,
		"example.com/acme/rules:v1",
		testDigest(),
		"bad signature",
		"failure_policy=warn_and_continue",
		"rules_usage=use_downloaded_rules",
		"verification_mode=offline",
		"expected_repository=" + baselineSignatureExpectedRepository,
		"expected_ref=" + baselineSignatureExpectedRef,
		"expected_issuer=" + baselineSignatureExpectedIssuer,
		"expected_subject=" + baselineSignatureExpectedSubject,
	} {
		if !strings.Contains(logOutput, want) {
			t.Fatalf("log missing %q: %s", want, logOutput)
		}
	}
}

func TestVerifyBaselineSignatureTrustedRootFailureWarnsAndSkipsVerifier(t *testing.T) {
	ref := mustParseReference(t, "example.com/acme/rules:v1")
	var calls int
	withBaselineSignatureHooks(t,
		testTrustedRoot(errors.New("root unavailable")),
		func(context.Context, name.Reference, *cosign.CheckOpts) ([]cosignoci.Signature, bool, error) {
			calls++
			return nil, true, nil
		},
	)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	verifyBaselineSignature(context.Background(), logger, "example.com/acme/rules:v1", ref, testDigest())

	if calls != 0 {
		t.Fatalf("verify should not be called after trusted root failure, got %d calls", calls)
	}
	if !strings.Contains(buf.String(), "load Sigstore trusted root") {
		t.Fatalf("log should include trusted root failure: %s", buf.String())
	}
}

func TestVerifyBaselineSignatureCachesTrustedRoot(t *testing.T) {
	ref := mustParseReference(t, "example.com/acme/rules:v1")
	var rootLoads int
	withBaselineSignatureHooks(t,
		func() (root.TrustedMaterial, error) {
			rootLoads++
			return &root.BaseTrustedMaterial{}, nil
		},
		func(context.Context, name.Reference, *cosign.CheckOpts) ([]cosignoci.Signature, bool, error) {
			return nil, true, nil
		},
	)

	verifyBaselineSignature(context.Background(), newTestLogger(), "example.com/acme/rules:v1", ref, testDigest())
	verifyBaselineSignature(context.Background(), newTestLogger(), "example.com/acme/rules:v1", ref, testDigest())

	if rootLoads != 1 {
		t.Fatalf("trusted root loads: got %d want 1", rootLoads)
	}
}

func TestPullVerifiesSignatureWithResolvedDigest(t *testing.T) {
	tr := newTestRegistry(t, testRegistryAddr)
	tr.publish(t, testRuleBundleA)

	var verifiedRef string
	withBaselineSignatureHooks(t,
		testTrustedRoot(nil),
		func(_ context.Context, got name.Reference, _ *cosign.CheckOpts) ([]cosignoci.Signature, bool, error) {
			verifiedRef = got.Name()
			return nil, true, nil
		},
	)

	loaded, digest, err := pull(context.Background(), tr.ref(t), newTestLogger())
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(loaded.RuleSets) != 1 {
		t.Fatalf("loaded rule sets: got %d want 1", len(loaded.RuleSets))
	}

	ref := mustParseReference(t, tr.ref(t))
	wantRef := ref.Context().Digest(digest).Name()
	if verifiedRef != wantRef {
		t.Fatalf("verified ref: got %q want %q", verifiedRef, wantRef)
	}
}

func TestPullVerifiesSignatureBeforeRulesLayerLoadFails(t *testing.T) {
	tr := newTestRegistry(t, testRegistryAddr)
	tr.publish(t, "not: valid: yaml:")

	var calls int
	withBaselineSignatureHooks(t,
		testTrustedRoot(nil),
		func(context.Context, name.Reference, *cosign.CheckOpts) ([]cosignoci.Signature, bool, error) {
			calls++
			return nil, true, nil
		},
	)

	_, _, err := pull(context.Background(), tr.ref(t), newTestLogger())
	if err == nil || !strings.Contains(err.Error(), "parse baseline rules bundle") {
		t.Fatalf("error: got %v want invalid rules bundle", err)
	}
	if calls != 1 {
		t.Fatalf("signature verifier calls: got %d want 1", calls)
	}
}

func TestParseRuleBundleGzip(t *testing.T) {
	loaded, err := parseRuleBundleGzip(bytes.NewReader(gzipBytes(t, validBaselineBundleYAML)), "sha256:test")
	if err != nil {
		t.Fatalf("parseRuleBundleGzip: %v", err)
	}
	if len(loaded.RuleSets) != 1 {
		t.Fatalf("rule_sets: got %d, want 1", len(loaded.RuleSets))
	}
	if loaded.RuleSets[0].RulesetID != "sample-smoke-proc-environ" {
		t.Fatalf("ruleset_id: got %q", loaded.RuleSets[0].RulesetID)
	}
	if loaded.RuleSets[0].Revision != "sha256:test" {
		t.Fatalf("ruleset revision: got %q", loaded.RuleSets[0].Revision)
	}
	if len(loaded.RuleModifiers) != 1 {
		t.Fatalf("rule_modifiers: got %d, want 1", len(loaded.RuleModifiers))
	}
	if loaded.RuleModifiers[0].Revision != "sha256:test" {
		t.Fatalf("modifier revision: got %q", loaded.RuleModifiers[0].Revision)
	}
}

func TestParseRuleBundleGzipRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantErrMsg string
	}{
		{
			name:       "not gzip",
			data:       []byte("not gzip"),
			wantErrMsg: "open baseline rules gzip",
		},
		{
			name:       "empty document",
			data:       gzipBytes(t, ""),
			wantErrMsg: "must contain rule_sets or rule_modifiers",
		},
		{
			name:       "invalid yaml",
			data:       gzipBytes(t, "rule_sets: ["),
			wantErrMsg: "parse baseline rules bundle",
		},
		{
			name:       "oversized bundle",
			data:       gzipBytes(t, strings.Repeat("x", maxBaselineRuleBundleBytes+1)),
			wantErrMsg: "baseline rules bundle exceeds maximum size",
		},
		{
			name: "invalid ruleset",
			data: gzipBytes(t, `rule_sets:
  - ruleset_id: invalid
    rules:
      - condition: "true"
        event_type: process_exec
        action: detect
`),
			wantErrMsg: "validate rule file rule bundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRuleBundleGzip(bytes.NewReader(tt.data), "sha256:test")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Fatalf("error: got %q, want containing %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

func TestBaselineLayerDescriptor(t *testing.T) {
	goodLayer := v1.Descriptor{
		MediaType: types.OCILayer,
	}
	tests := []struct {
		name       string
		manifest   *v1.Manifest
		wantErrMsg string
	}{
		{
			name: "valid layers regardless of metadata",
			manifest: &v1.Manifest{
				MediaType: types.OCIManifestSchema1,
				Config: v1.Descriptor{
					MediaType: types.OCIConfigJSON,
					Data:      []byte(`{}`),
				},
				Layers: []v1.Descriptor{goodLayer},
			},
		},
		{
			name: "valid config media type mismatch",
			manifest: &v1.Manifest{
				MediaType: types.OCIManifestSchema1,
				Config:    v1.Descriptor{MediaType: types.MediaType("application/vnd.example.wrong.config.v1+json")},
				Layers:    []v1.Descriptor{goodLayer},
			},
		},
		{
			name: "valid config data mismatch",
			manifest: &v1.Manifest{
				MediaType: types.OCIManifestSchema1,
				Config: v1.Descriptor{
					MediaType: types.OCIConfigJSON,
					Data:      []byte(`{"schema_version":1,"kind":"wrong"}`),
				},
				Layers: []v1.Descriptor{goodLayer},
			},
		},
		{
			name: "manifest media type mismatch",
			manifest: &v1.Manifest{
				MediaType: types.DockerManifestSchema2,
				Config:    v1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers:    []v1.Descriptor{goodLayer},
			},
			wantErrMsg: "manifest media type",
		},
		{
			name: "zero layers",
			manifest: &v1.Manifest{
				MediaType: types.OCIManifestSchema1,
				Config:    v1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers:    nil,
			},
			wantErrMsg: "exactly 1 layer",
		},
		{
			name: "multiple layers",
			manifest: &v1.Manifest{
				MediaType: types.OCIManifestSchema1,
				Config:    v1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers:    []v1.Descriptor{{MediaType: types.OCILayer}, goodLayer},
			},
			wantErrMsg: "exactly 1 layer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := baselineLayerDescriptor(tt.manifest)
			if tt.wantErrMsg == "" {
				if err != nil {
					t.Fatalf("baselineLayerDescriptor: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Fatalf("error: got %q want substring %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

func TestBaselineRevision(t *testing.T) {
	manifest := &v1.Manifest{
		Annotations: map[string]string{ociVersionAnnotation: "v20260618-001"},
	}
	if got := baselineRevision(manifest, "sha256:fallback"); got != "v20260618-001" {
		t.Fatalf("revision with annotation: got %q", got)
	}
	if got := baselineRevision(&v1.Manifest{}, "sha256:fallback"); got != "sha256:fallback" {
		t.Fatalf("revision fallback: got %q", got)
	}
}

func TestLoadBaselineRulesFromLayer(t *testing.T) {
	t.Run("valid rules bundle", func(t *testing.T) {
		img := imageWithLayers(t,
			static.NewLayer(gzipBytes(t, validBaselineBundleYAML), types.OCILayer),
		)
		manifest, err := img.Manifest()
		if err != nil {
			t.Fatalf("manifest: %v", err)
		}
		loaded, err := loadBaselineRulesFromLayer(img, manifest.Layers[0], "sha256:test")
		if err != nil {
			t.Fatalf("loadBaselineRulesFromLayer: %v", err)
		}
		if len(loaded.RuleSets) != 1 || len(loaded.RuleModifiers) != 1 {
			t.Fatalf("loaded rules: got rule_sets=%d rule_modifiers=%d", len(loaded.RuleSets), len(loaded.RuleModifiers))
		}
	})

	t.Run("invalid rules bundle", func(t *testing.T) {
		img := imageWithLayers(t,
			static.NewLayer(gzipBytes(t, "not: valid: yaml:"), types.OCILayer),
		)
		manifest, err := img.Manifest()
		if err != nil {
			t.Fatalf("manifest: %v", err)
		}
		_, err = loadBaselineRulesFromLayer(img, manifest.Layers[0], "sha256:test")
		if err == nil || !strings.Contains(err.Error(), "parse baseline rules bundle") {
			t.Fatalf("error: got %v want invalid rules bundle", err)
		}
	})
}

func testTrustedRoot(err error) func() (root.TrustedMaterial, error) {
	return func() (root.TrustedMaterial, error) {
		if err != nil {
			return nil, err
		}
		return &root.BaseTrustedMaterial{}, nil
	}
}

func withBaselineSignatureHooks(t *testing.T, loadTrustedRoot func() (root.TrustedMaterial, error), verify imageSignatureVerifier) {
	t.Helper()
	oldLoadTrustedRoot := loadBaselineTrustedRoot
	oldVerify := verifyBaselineSignatureBundle
	loadBaselineTrustedRoot = sync.OnceValues(loadTrustedRoot)
	verifyBaselineSignatureBundle = verify
	t.Cleanup(func() {
		loadBaselineTrustedRoot = oldLoadTrustedRoot
		verifyBaselineSignatureBundle = oldVerify
	})
}

func mustParseReference(t *testing.T, refStr string) name.Reference {
	t.Helper()
	ref, err := name.ParseReference(refStr)
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	return ref
}

func testDigest() string {
	return "sha256:" + strings.Repeat("a", 64)
}

func imageWithLayers(t *testing.T, layers ...v1.Layer) v1.Image {
	t.Helper()

	img := empty.Image
	for _, layer := range layers {
		var err error
		img, err = mutate.Append(img, mutate.Addendum{Layer: layer})
		if err != nil {
			t.Fatalf("append layer: %v", err)
		}
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	return img
}

func gzipBytes(t *testing.T, content string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(content)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}
