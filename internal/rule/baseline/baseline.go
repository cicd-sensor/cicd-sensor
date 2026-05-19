package baseline

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

const (
	GitHubOCIRef = "ghcr.io/rung/rules:v1"
	GitLabOCIRef = "registry.gitlab.com/rung/oci-testing/rules:v1"
	QuayOCIRef   = "quay.io/cicd-sensor/cicd-sensor-rules:v1"

	ociVersionAnnotation = "org.opencontainers.image.version"

	maxBaselineRuleBundleBytes = 10 * 1024 * 1024

	defaultCacheTTL       = 60 * time.Second
	defaultRefreshTimeout = 60 * time.Second
	sourcePullAttempts    = 2
)

var sourcePullRetryDelay = time.Second

type source struct {
	name string
	ref  string
}

// Cache keeps the pulled baseline rules for one manager process.
type Cache struct {
	ttl time.Duration

	mu      sync.Mutex
	rules   rulesource.LoadedRules
	ref     string
	digest  string
	fetched time.Time
}

func NewCache() *Cache {
	return &Cache{ttl: defaultCacheTTL}
}

var defaultCache = NewCache()

// LoadForProvider uses the process-global cache for agent paths that do not
// own a manager Server instance.
func LoadForProvider(ctx context.Context, logger *slog.Logger, provider string) (rulesource.LoadedRules, error) {
	return defaultCache.LoadForProvider(ctx, logger, provider)
}

// LoadForProvider returns baseline rules, preferring the provider's registry.
func (c *Cache) LoadForProvider(ctx context.Context, logger *slog.Logger, provider string) (rulesource.LoadedRules, error) {
	if c == nil {
		c = NewCache()
	}
	return c.get(ctx, logger, sourcesForProvider(provider))
}

func sourcesForProvider(provider string) []source {
	switch provider {
	case "gitlab":
		return []source{
			{name: "gitlab", ref: GitLabOCIRef},
			{name: "quay", ref: QuayOCIRef},
			{name: "github", ref: GitHubOCIRef},
		}
	default:
		return []source{
			{name: "github", ref: GitHubOCIRef},
			{name: "quay", ref: QuayOCIRef},
			{name: "gitlab", ref: GitLabOCIRef},
		}
	}
}

func (c *Cache) get(ctx context.Context, logger *slog.Logger, sources []source) (rulesource.LoadedRules, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.rules.RuleSets) > 0 || len(c.rules.RuleModifiers) > 0 {
		if time.Since(c.fetched) < c.ttl {
			return c.rules, nil
		}
	}

	refreshCtx, cancel := context.WithTimeout(ctx, defaultRefreshTimeout)
	defer cancel()

	if c.digest != "" && c.ref != "" && len(sources) > 0 && c.ref == sources[0].ref {
		if unchanged, err := sourceDigestMatches(refreshCtx, c.ref, c.digest); err == nil && unchanged {
			c.fetched = time.Now()
			if logger != nil {
				logger.InfoContext(ctx, "baseline_unchanged",
					"oci_ref", c.ref,
					"digest", c.digest,
				)
			}
			return c.rules, nil
		}
	}

	loaded, ref, digest, err := pullFromSources(refreshCtx, sources, logger)
	if err != nil {
		return rulesource.LoadedRules{}, err
	}
	c.rules = loaded
	c.ref = ref
	c.digest = digest
	c.fetched = time.Now()
	return loaded, nil
}

func sourceDigestMatches(ctx context.Context, refStr string, digest string) (bool, error) {
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return false, err
	}
	desc, err := remote.Head(ref, remote.WithContext(ctx))
	if err != nil {
		return false, err
	}
	return desc.Digest.String() == digest, nil
}

func pullFromSources(ctx context.Context, sources []source, logger *slog.Logger) (rulesource.LoadedRules, string, string, error) {
	var errs []error
	for _, src := range sources {
		for attempt := 1; attempt <= sourcePullAttempts; attempt++ {
			loaded, digest, err := pull(ctx, src.ref, logger)
			if err == nil {
				return loaded, src.ref, digest, nil
			}
			errs = append(errs, fmt.Errorf("%s %s attempt %d: %w", src.name, src.ref, attempt, err))
			if attempt < sourcePullAttempts {
				time.Sleep(sourcePullRetryDelay)
			}
		}
	}
	return rulesource.LoadedRules{}, "", "", errors.Join(errs...)
}

func pull(ctx context.Context, refStr string, logger *slog.Logger) (rulesource.LoadedRules, string, error) {
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return rulesource.LoadedRules{}, "", fmt.Errorf("parse baseline OCI ref %q: %w", refStr, err)
	}

	img, err := remote.Image(ref, remote.WithContext(ctx))
	if err != nil {
		return rulesource.LoadedRules{}, "", fmt.Errorf("fetch baseline image %q: %w", refStr, err)
	}

	manifest, err := img.Manifest()
	if err != nil {
		return rulesource.LoadedRules{}, "", fmt.Errorf("read baseline manifest: %w", err)
	}
	layerDesc, err := baselineLayerDescriptor(manifest)
	if err != nil {
		return rulesource.LoadedRules{}, "", err
	}

	digest, err := img.Digest()
	if err != nil {
		return rulesource.LoadedRules{}, "", fmt.Errorf("read baseline digest: %w", err)
	}

	revision := baselineRevision(manifest, digest.String())
	loaded, err := loadBaselineRulesFromLayer(img, layerDesc, revision)
	if err != nil {
		return rulesource.LoadedRules{}, "", fmt.Errorf("load baseline rules layer: %w", err)
	}
	if logger != nil {
		logger.InfoContext(ctx, "baseline_pulled",
			"oci_ref", refStr,
			"digest", digest.String(),
			"revision", revision,
			"rule_sets", len(loaded.RuleSets),
			"rule_modifiers", len(loaded.RuleModifiers),
		)
	}
	return loaded, digest.String(), nil
}

func baselineLayerDescriptor(manifest *v1.Manifest) (v1.Descriptor, error) {
	if manifest.MediaType != types.OCIManifestSchema1 {
		return v1.Descriptor{}, fmt.Errorf("baseline OCI artifact manifest media type %q does not match expected %q", manifest.MediaType, types.OCIManifestSchema1)
	}
	if len(manifest.Layers) != 1 {
		return v1.Descriptor{}, fmt.Errorf("baseline OCI artifact must have exactly 1 layer, got %d", len(manifest.Layers))
	}
	// Registry metadata is only a hint; the real contract is that the single
	// layer decodes as a valid cicd-sensor rule bundle. Authenticity belongs to
	// future Cosign/digest verification, not media type checks.
	return manifest.Layers[0], nil
}

func baselineRevision(manifest *v1.Manifest, fallback string) string {
	if manifest != nil && manifest.Annotations != nil {
		if version := manifest.Annotations[ociVersionAnnotation]; version != "" {
			return version
		}
	}
	return fallback
}

func loadBaselineRulesFromLayer(img v1.Image, layerDesc v1.Descriptor, revision string) (rulesource.LoadedRules, error) {
	layer, err := img.LayerByDigest(layerDesc.Digest)
	if err != nil {
		return rulesource.LoadedRules{}, fmt.Errorf("open layer: %w", err)
	}
	layerReader, err := layer.Compressed()
	if err != nil {
		return rulesource.LoadedRules{}, fmt.Errorf("open layer reader: %w", err)
	}
	defer layerReader.Close()
	return parseRuleBundleGzip(layerReader, revision)
}

func parseRuleBundleGzip(r io.Reader, revision string) (rulesource.LoadedRules, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return rulesource.LoadedRules{}, fmt.Errorf("open baseline rules gzip: %w", err)
	}
	defer gz.Close()

	data, err := io.ReadAll(io.LimitReader(gz, maxBaselineRuleBundleBytes+1))
	if err != nil {
		return rulesource.LoadedRules{}, fmt.Errorf("read baseline rules bundle: %w", err)
	}
	if len(data) > maxBaselineRuleBundleBytes {
		return rulesource.LoadedRules{}, fmt.Errorf("baseline rules bundle exceeds maximum size %d bytes", maxBaselineRuleBundleBytes)
	}

	loaded, err := rulesource.LoadRulesBytes(data, revision)
	if err != nil {
		return rulesource.LoadedRules{}, fmt.Errorf("parse baseline rules bundle: %w", err)
	}
	if len(loaded.RuleSets) == 0 && len(loaded.RuleModifiers) == 0 {
		return rulesource.LoadedRules{}, errors.New("baseline OCI artifact contains no rules")
	}
	return *loaded, nil
}
