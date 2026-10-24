package manager

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/authn"
	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	oidcauth "github.com/cicd-sensor/cicd-sensor/internal/managerauth/oidc"
)

// TokenStore stores token hashes so raw bearer tokens do not stay in memory.
type TokenStore struct {
	hashes [][32]byte
}

// NewTokenStore accepts full sk_cs_ bearer tokens and keeps only valid hashes.
func NewTokenStore(tokens []string) *TokenStore {
	hashes := make([][32]byte, 0, len(tokens))
	for _, token := range tokens {
		if !IsValidToken(token) {
			continue
		}
		hashes = append(hashes, sha256.Sum256([]byte(token)))
	}
	return &TokenStore{hashes: hashes}
}

// Len returns the number of stored token hashes.
func (s *TokenStore) Len() int {
	if s == nil {
		return 0
	}
	return len(s.hashes)
}

// IsValidToken reports whether token is a full cicd-sensor manager bearer.
func IsValidToken(token string) bool {
	return managerauth.IsValidToken(token)
}

// validateToken reports whether the bearer token matches any stored hash.
// Hash comparison is constant-time per candidate; a match against any
// configured rotation token is accepted.
func (s *TokenStore) validateToken(token string) bool {
	if s == nil || !IsValidToken(token) {
		return false
	}
	got := sha256.Sum256([]byte(token))
	for _, want := range s.hashes {
		if subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
			return true
		}
	}
	return false
}

// parseBearerCredential accepts Authorization: Bearer <credential> without
// inspecting the credential shape. Manager-token vs id-token routing uses
// Cicd-Sensor-Token-Type.
func parseBearerCredential(h string) (string, bool) {
	parts := strings.Fields(h)
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	if parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// authPrincipal is the authenticated caller attached to the request context.
type authPrincipal struct {
	Kind              string
	Repository        string
	RepositoryOwner   string
	RepositoryID      string
	RepositoryOwnerID string
	Ref               string
	EventName         string
}

func (p authPrincipal) isOIDC() bool {
	return p.Kind == oidcauth.AuthKindIDToken
}

type authMiddlewareOptions struct {
	tokens *TokenStore
	oidc   *oidcauth.Verifier
	oidcOn bool
}

// newAuthMiddleware enforces manager auth before Connect decodes the request.
// That keeps large collector bodies out of the RPC layer until the credential
// is accepted, and one HTTP boundary covers every mounted Connect service.
func newAuthMiddleware(logger *slog.Logger, opts authMiddlewareOptions) *authn.Middleware {
	authLogger := logger.With("component", "auth_middleware")
	auth := func(ctx context.Context, r *http.Request) (any, error) {
		if opts.tokens == nil && !opts.oidcOn {
			authLogger.ErrorContext(ctx, "manager_auth_misconfigured",
				"procedure", procedureFromRequest(r),
			)
			return nil, authn.Errorf("misconfigured server")
		}

		cred, ok := parseBearerCredential(r.Header.Get("Authorization"))
		if !ok {
			authLogger.WarnContext(ctx, "manager_auth_failed",
				"procedure", procedureFromRequest(r),
				"peer", r.RemoteAddr,
				"reason", "missing_or_malformed_bearer",
			)
			return nil, bearerAuthError()
		}

		tokenType := strings.TrimSpace(r.Header.Get(oidcauth.TokenTypeHeader))
		if tokenType == "" {
			tokenType = oidcauth.TokenTypeManagerToken
		}

		switch tokenType {
		case oidcauth.TokenTypeManagerToken:
			if opts.tokens == nil || !opts.tokens.validateToken(cred) {
				authLogger.WarnContext(ctx, "manager_auth_failed",
					"procedure", procedureFromRequest(r),
					"peer", r.RemoteAddr,
					"auth_kind", oidcauth.AuthKindManagerToken,
				)
				return nil, bearerAuthError()
			}
			authLogger.InfoContext(ctx, "manager_auth_accepted",
				"procedure", procedureFromRequest(r),
				"auth_kind", oidcauth.AuthKindManagerToken,
			)
			return authPrincipal{Kind: oidcauth.AuthKindManagerToken}, nil

		case oidcauth.TokenTypeIDToken:
			if !opts.oidcOn || opts.oidc == nil {
				authLogger.WarnContext(ctx, "manager_auth_failed",
					"procedure", procedureFromRequest(r),
					"peer", r.RemoteAddr,
					"auth_kind", oidcauth.AuthKindIDToken,
					"reason", "oidc_disabled",
				)
				return nil, bearerAuthError()
			}
			principal, err := opts.oidc.Verify(ctx, cred)
			if err != nil {
				if errors.Is(err, oidcauth.ErrFetchingKeys) || strings.Contains(err.Error(), "fetching keys") {
					authLogger.ErrorContext(ctx, "manager_oidc_jwks_unavailable",
						"procedure", procedureFromRequest(r),
						"peer", r.RemoteAddr,
						"error", err,
					)
					return nil, connect.NewError(connect.CodeUnavailable, errors.New("oidc key set unavailable"))
				}
				authLogger.WarnContext(ctx, "manager_auth_failed",
					"procedure", procedureFromRequest(r),
					"peer", r.RemoteAddr,
					"auth_kind", oidcauth.AuthKindIDToken,
				)
				return nil, bearerAuthError()
			}
			authLogger.InfoContext(ctx, "manager_auth_oidc_accepted",
				"procedure", procedureFromRequest(r),
				"auth_kind", principal.Kind,
				"repository", principal.Claims.Repository,
				"repository_owner", principal.Claims.RepositoryOwner,
				"ref", principal.Claims.Ref,
				"event_name", principal.Claims.EventName,
			)
			return authPrincipal{
				Kind:              principal.Kind,
				Repository:        principal.Claims.Repository,
				RepositoryOwner:   principal.Claims.RepositoryOwner,
				RepositoryID:      principal.Claims.RepositoryID,
				RepositoryOwnerID: principal.Claims.RepositoryOwnerID,
				Ref:               principal.Claims.Ref,
				EventName:         principal.Claims.EventName,
			}, nil

		default:
			authLogger.WarnContext(ctx, "manager_auth_failed",
				"procedure", procedureFromRequest(r),
				"peer", r.RemoteAddr,
				"reason", "unknown_token_type",
			)
			return nil, bearerAuthError()
		}
	}
	return authn.NewMiddleware(auth)
}

// bearerAuthError returns the standard Bearer challenge without exposing
// whether the token was missing, malformed, or simply wrong.
func bearerAuthError() error {
	err := authn.Errorf("unauthorized")
	err.Meta().Set("WWW-Authenticate", "Bearer")
	return err
}

// procedureFromRequest prefers the Connect procedure name for auth logs.
// Non-RPC traffic falls back to the raw path so failed probes remain useful.
func procedureFromRequest(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	if proc, ok := authn.InferProcedure(r.URL); ok {
		return proc
	}
	return r.URL.Path
}

func principalFromContext(ctx context.Context) (authPrincipal, bool) {
	info := authn.GetInfo(ctx)
	if info == nil {
		return authPrincipal{}, false
	}
	p, ok := info.(authPrincipal)
	return p, ok
}
