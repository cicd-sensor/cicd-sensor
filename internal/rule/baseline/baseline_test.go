package baseline

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const validBaselineBundleYAML = `rule_sets:
  - ruleset_id: sample-smoke-proc-environ
    rules:
      - rule_id: proc_environ_read
        description: Detect reads of /proc/<pid>/environ.
        event_kind: file_open
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
        event_kind: process_exec
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
