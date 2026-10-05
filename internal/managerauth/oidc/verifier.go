package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrFetchingKeys is returned when the remote JWKS cannot be fetched.
// Callers map it to Unavailable so clients retry without treating it as an
// auth oracle.
var ErrFetchingKeys = errors.New("fetching oidc keys")

// Principal is the authenticated OIDC identity attached to a request.
type Principal struct {
	Kind    string
	Claims  Claims
	Matched AllowEntry
}

// Verifier validates GitHub Actions ID tokens against a configured issuer,
// audience, JWKS URL, and exact-claim allowlist.
type Verifier struct {
	cfg      Config
	verifier *oidc.IDTokenVerifier
}

// NewVerifier builds a go-oidc verifier that loads JWKS from cfg.JWKSURL.
// Discovery is intentionally skipped so Manager startup does not block on the
// issuer being reachable.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	keySet := oidc.NewRemoteKeySet(ctx, cfg.JWKSURL)
	return NewVerifierWithKeySet(cfg, keySet), nil
}

// NewVerifierWithKeySet builds a verifier with an explicit key set. Tests use
// a StaticKeySet; production uses NewRemoteKeySet via NewVerifier.
func NewVerifierWithKeySet(cfg Config, keySet oidc.KeySet) *Verifier {
	return &Verifier{
		cfg: cfg,
		verifier: oidc.NewVerifier(cfg.Issuer, keySet, &oidc.Config{
			ClientID: cfg.Audience,
		}),
	}
}

// Verify checks the JWT signature and standard claims, then authorizes against
// the exact-claim allowlist.
func (v *Verifier) Verify(ctx context.Context, rawJWT string) (Principal, error) {
	if v == nil || v.verifier == nil {
		return Principal{}, fmt.Errorf("oidc verifier is nil")
	}
	token, err := v.verifier.Verify(ctx, rawJWT)
	if err != nil {
		if isFetchingKeysError(err) {
			return Principal{}, fmt.Errorf("%w: %w", ErrFetchingKeys, err)
		}
		return Principal{}, fmt.Errorf("verify id token: %w", err)
	}

	var claims struct {
		Repository        string `json:"repository"`
		RepositoryOwner   string `json:"repository_owner"`
		RepositoryID      string `json:"repository_id"`
		RepositoryOwnerID string `json:"repository_owner_id"`
		Ref               string `json:"ref"`
		EventName         string `json:"event_name"`
	}
	if err := token.Claims(&claims); err != nil {
		return Principal{}, fmt.Errorf("decode id token claims: %w", err)
	}

	matchedClaims := Claims{
		Repository:        claims.Repository,
		RepositoryOwner:   claims.RepositoryOwner,
		RepositoryID:      claims.RepositoryID,
		RepositoryOwnerID: claims.RepositoryOwnerID,
		Ref:               claims.Ref,
		EventName:         claims.EventName,
	}
	matched, ok := Match(v.cfg.Allow, matchedClaims)
	if !ok {
		return Principal{}, fmt.Errorf("id token claims not allowlisted")
	}
	return Principal{
		Kind:    AuthKindIDToken,
		Claims:  matchedClaims,
		Matched: matched,
	}, nil
}

func isFetchingKeysError(err error) bool {
	if err == nil {
		return false
	}
	// go-oidc wraps JWKS HTTP failures as "fetching keys %w".
	return strings.Contains(err.Error(), "fetching keys")
}
