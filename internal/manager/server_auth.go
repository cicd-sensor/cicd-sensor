package manager

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/authn"
	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
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

// parseManagerBearer accepts only Authorization: Bearer sk_cs_...
func parseManagerBearer(h string) (string, bool) {
	parts := strings.Fields(h)
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := parts[1]
	if !IsValidToken(token) {
		return "", false
	}
	return token, true
}

// authPrincipal is intentionally empty while manager auth uses shared bearer
// tokens. It keeps the authn context boundary ready for future scoped tokens.
type authPrincipal struct{}

// newAuthMiddleware enforces manager auth before Connect decodes the request.
// That keeps large collector bodies out of the RPC layer until the bearer is
// accepted, and one HTTP boundary covers every mounted Connect service.
func newAuthMiddleware(logger *slog.Logger, tokens *TokenStore, opts ...any) *authn.Middleware {
	authLogger := logger.With("component", "auth_middleware")
	auth := func(ctx context.Context, r *http.Request) (any, error) {
		if tokens == nil {
			authLogger.ErrorContext(ctx, "manager_auth_misconfigured",
				"procedure", procedureFromRequest(r),
			)
			return nil, authn.Errorf("misconfigured server")
		}
		token, ok := parseManagerBearer(r.Header.Get("Authorization"))
		if !ok || !tokens.validateToken(token) {
			authLogger.WarnContext(ctx, "manager_auth_failed",
				"procedure", procedureFromRequest(r),
				"peer", r.RemoteAddr,
			)
			return nil, bearerAuthError()
		}
		return authPrincipal{}, nil
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
