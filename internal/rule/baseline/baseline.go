package baseline

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	cosign "github.com/sigstore/cosign/v3/pkg/cosign"
	cosignoci "github.com/sigstore/cosign/v3/pkg/oci"
	cosignremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

const (
	GitHubOCIRef = "ghcr.io/cicd-sensor/cicd-sensor-rules:v1"
	GitLabOCIRef = "registry.gitlab.com/cicd-sensor/cicd-sensor-rules:v1"
	QuayOCIRef   = "quay.io/cicd-sensor/cicd-sensor-rules:v1"

	ociVersionAnnotation = "org.opencontainers.image.version"

	maxBaselineRuleBundleBytes = 10 * 1024 * 1024

	defaultCacheTTL       = 60 * time.Second
	defaultRefreshTimeout = 60 * time.Second
	sourcePullAttempts    = 2

	baselineSignatureExpectedRepository = "cicd-sensor/cicd-sensor"
	baselineSignatureExpectedRef        = "refs/heads/main"
	baselineSignatureExpectedIssuer     = "https://token.actions.githubusercontent.com"
	baselineSignatureExpectedSubject    = `^https://github\.com/cicd-sensor/cicd-sensor/.+@refs/heads/main$`
	baselineSignatureExpectedPredicate  = "https://sigstore.dev/cosign/sign/v1"

	baselineSignatureVerificationWarning = "baseline_signature_unverified"
)

var sourcePullRetryDelay = time.Second

type imageSignatureVerifier func(context.Context, name.Reference, *cosign.CheckOpts) ([]cosignoci.Signature, bool, error)

var loadBaselineTrustedRoot = sync.OnceValues(cosign.TrustedRoot)
var verifyBaselineSignatureBundle imageSignatureVerifier = verifyBaselineCosignBundle

func baselineSignatureCheckOpts(trustedMaterial root.TrustedMaterial) *cosign.CheckOpts {
	return &cosign.CheckOpts{
		TrustedMaterial:              trustedMaterial,
		RegistryClientOpts:           []cosignremote.Option{cosignremote.WithRemoteOptions(remote.WithAuth(authn.Anonymous))},
		Offline:                      true,
		NewBundleFormat:              true,
		ClaimVerifier:                baselineCosignSignClaimVerifier,
		Identities:                   []cosign.Identity{{Issuer: baselineSignatureExpectedIssuer, SubjectRegExp: baselineSignatureExpectedSubject}},
		CertGithubWorkflowRepository: baselineSignatureExpectedRepository,
		CertGithubWorkflowRef:        baselineSignatureExpectedRef,
	}
}

func baselineCosignSignClaimVerifier(sig cosignoci.Signature, imageDigest v1.Hash, _ map[string]interface{}) error {
	payload, err := sig.Payload()
	if err != nil {
		return err
	}
	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("parse cosign bundle DSSE envelope: %w", err)
	}
	statementBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decode cosign bundle DSSE payload: %w", err)
	}
	var statement struct {
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(statementBytes, &statement); err != nil {
		return fmt.Errorf("parse cosign bundle statement: %w", err)
	}
	if statement.PredicateType != baselineSignatureExpectedPredicate {
		return fmt.Errorf("unexpected cosign bundle predicate type %q", statement.PredicateType)
	}
	for _, subject := range statement.Subject {
		if subject.Digest["sha256"] == imageDigest.Hex {
			return nil
		}
	}
	return fmt.Errorf("cosign bundle subject does not match image digest %s", imageDigest.String())
}

func verifyBaselineCosignBundle(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]cosignoci.Signature, bool, error) {
	return cosign.VerifyImageAttestations(ctx, ref, co)
}

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
	verifyBaselineSignature(ctx, logger, refStr, ref, digest.String())

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

func verifyBaselineSignature(ctx context.Context, logger *slog.Logger, refStr string, ref name.Reference, digest string) {
	trustedMaterial, err := loadBaselineTrustedRoot()
	if err != nil {
		err = fmt.Errorf("load Sigstore trusted root: %w", err)
	} else {
		digestRef := ref.Context().Digest(digest)
		_, _, err = verifyBaselineSignatureBundle(ctx, digestRef, baselineSignatureCheckOpts(trustedMaterial))
	}
	if err != nil && logger != nil {
		logger.WarnContext(ctx, baselineSignatureVerificationWarning,
			"oci_ref", refStr,
			"digest", digest,
			"error", err,
			"failure_policy", "warn_and_continue",
			"rules_usage", "use_downloaded_rules",
			"verification_mode", "offline",
			"expected_repository", baselineSignatureExpectedRepository,
			"expected_ref", baselineSignatureExpectedRef,
			"expected_issuer", baselineSignatureExpectedIssuer,
			"expected_subject", baselineSignatureExpectedSubject,
			"expected_predicate", baselineSignatureExpectedPredicate,
		)
	}
}

func baselineLayerDescriptor(manifest *v1.Manifest) (v1.Descriptor, error) {
	if manifest.MediaType != types.OCIManifestSchema1 {
		return v1.Descriptor{}, fmt.Errorf("baseline OCI artifact manifest media type %q does not match expected %q", manifest.MediaType, types.OCIManifestSchema1)
	}
	if len(manifest.Layers) != 1 {
		return v1.Descriptor{}, fmt.Errorf("baseline OCI artifact must have exactly 1 layer, got %d", len(manifest.Layers))
	}
	// Registry metadata is only a hint; the real contract is that the single
	// layer decodes as a valid cicd-sensor rule bundle. Signature verification
	// is performed separately and is fail-open for availability.
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
