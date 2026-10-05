// Package oidc verifies GitHub Actions ID tokens for Manager auth.
package oidc

import (
	"fmt"
	"strings"
)

// TokenTypeHeader is the HTTP header that declares which credential kind is
// carried in Authorization: Bearer. Values name the token type, not the
// HTTP auth scheme.
const TokenTypeHeader = "Cicd-Sensor-Token-Type"

// Token type header values.
const (
	TokenTypeManagerToken = "manager-token"
	TokenTypeIDToken      = "id-token"
)

// AuthKind identifies the authenticated principal kind stored in context.
const (
	AuthKindManagerToken = "manager-token"
	AuthKindIDToken      = "id-token"
)

// Config is the Manager-side OIDC verifier configuration.
type Config struct {
	Enabled  bool
	Issuer   string
	Audience string
	JWKSURL  string
	Allow    []AllowEntry
}

// AllowEntry is one exact-claim allowlist grant. Non-empty fields must all
// match the corresponding JWT claims. Empty string means the claim is
// unconstrained (YAML key omitted). Explicit empty YAML values must be
// rejected before constructing an AllowEntry (see AllowEntryFromOptional).
type AllowEntry struct {
	RepositoryOwner   string
	Repository        string
	RepositoryOwnerID string
	RepositoryID      string
}

// AllowEntryFromOptional builds an AllowEntry from optional claim pointers.
// A nil pointer means the YAML key was omitted (no constraint). A non-nil
// pointer must carry a non-empty, non-whitespace claim value; explicit
// empty or whitespace-only values are rejected.
func AllowEntryFromOptional(repositoryOwner, repository, repositoryOwnerID, repositoryID *string) (AllowEntry, error) {
	owner, err := optionalClaim(repositoryOwner, "repository_owner")
	if err != nil {
		return AllowEntry{}, err
	}
	repo, err := optionalClaim(repository, "repository")
	if err != nil {
		return AllowEntry{}, err
	}
	ownerID, err := optionalClaim(repositoryOwnerID, "repository_owner_id")
	if err != nil {
		return AllowEntry{}, err
	}
	repoID, err := optionalClaim(repositoryID, "repository_id")
	if err != nil {
		return AllowEntry{}, err
	}
	return AllowEntry{
		RepositoryOwner:   owner,
		Repository:        repo,
		RepositoryOwnerID: ownerID,
		RepositoryID:      repoID,
	}, nil
}

func optionalClaim(p *string, name string) (string, error) {
	if p == nil {
		return "", nil
	}
	v := strings.TrimSpace(*p)
	if v == "" {
		return "", fmt.Errorf("%s must not be empty", name)
	}
	if v != *p {
		return "", fmt.Errorf("%s must not be empty or whitespace-only", name)
	}
	return v, nil
}

// Validate reports whether cfg is complete enough to construct a verifier.
// Callers that leave OIDC disabled skip this.
func (cfg Config) Validate() error {
	if !cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.Issuer) == "" {
		return fmt.Errorf("auth.oidc.issuer is required when auth.oidc.enabled is true")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return fmt.Errorf("auth.oidc.audience is required when auth.oidc.enabled is true")
	}
	if strings.TrimSpace(cfg.JWKSURL) == "" {
		return fmt.Errorf("auth.oidc.jwks_url is required when auth.oidc.enabled is true")
	}
	if len(cfg.Allow) == 0 {
		return fmt.Errorf("auth.oidc.allow must be non-empty when auth.oidc.enabled is true")
	}
	for i, entry := range cfg.Allow {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("auth.oidc.allow[%d]: %w", i, err)
		}
	}
	return nil
}

// Validate checks one allowlist entry.
func (e AllowEntry) Validate() error {
	owner := strings.TrimSpace(e.RepositoryOwner)
	repo := strings.TrimSpace(e.Repository)
	ownerID := strings.TrimSpace(e.RepositoryOwnerID)
	repoID := strings.TrimSpace(e.RepositoryID)

	if owner == "" && repo == "" && ownerID == "" && repoID == "" {
		return fmt.Errorf("entry must name at least one known claim key (repository_owner, repository, repository_owner_id, repository_id)")
	}
	// ID-only entries are rejected: grants must identify a named owner or repo.
	if owner == "" && repo == "" {
		return fmt.Errorf("entry must include repository_owner or repository")
	}
	if e.RepositoryOwner != owner || e.Repository != repo || e.RepositoryOwnerID != ownerID || e.RepositoryID != repoID {
		return fmt.Errorf("claim values must not be empty or whitespace-only")
	}
	if owner != "" && strings.Contains(owner, "/") {
		return fmt.Errorf("repository_owner must not contain '/'")
	}
	if repo != "" && !strings.Contains(repo, "/") {
		return fmt.Errorf("repository must be owner/name")
	}
	return nil
}
