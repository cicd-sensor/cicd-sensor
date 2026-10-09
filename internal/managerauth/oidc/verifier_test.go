package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	jwt "github.com/golang-jwt/jwt/v5"

	oidcauth "github.com/cicd-sensor/cicd-sensor/internal/managerauth/oidc"
)

const (
	testIssuer   = "https://token.actions.githubusercontent.com"
	testAudience = "https://cicd-sensor-manager.example.com"
)

func TestVerifierMatrix(t *testing.T) {
	key := mustRSAKey(t)
	cfg := oidcauth.Config{
		Enabled:  true,
		Issuer:   testIssuer,
		Audience: testAudience,
		JWKSURL:  "unused",
		Allow: []oidcauth.AllowEntry{
			{RepositoryOwner: "acme-corp"},
			{Repository: "partner-org/payments"},
		},
	}
	verifier := oidcauth.NewVerifierWithKeySet(cfg, &gooidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{&key.PublicKey},
	})

	now := time.Now()
	raw := mustSignJWT(t, key, jwtClaims{
		Issuer:            testIssuer,
		Subject:           "repo:acme-corp/api:ref:refs/heads/main",
		Audience:          []string{testAudience},
		Expiry:            now.Add(5 * time.Minute),
		IssuedAt:          now,
		NotBefore:         now.Add(-time.Minute),
		Repository:        "acme-corp/api",
		RepositoryOwner:   "acme-corp",
		RepositoryID:      "1",
		RepositoryOwnerID: "10",
	})

	principal, err := verifier.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if principal.Kind != oidcauth.AuthKindIDToken {
		t.Fatalf("kind: got %q", principal.Kind)
	}
	if principal.Claims.Repository != "acme-corp/api" {
		t.Fatalf("repository: got %q", principal.Claims.Repository)
	}

	t.Run("wrong audience", func(t *testing.T) {
		bad := mustSignJWT(t, key, jwtClaims{
			Issuer: testIssuer, Audience: []string{"https://other.example"},
			Expiry: now.Add(time.Minute), IssuedAt: now, NotBefore: now.Add(-time.Minute),
			Repository: "acme-corp/api", RepositoryOwner: "acme-corp",
		})
		if _, err := verifier.Verify(context.Background(), bad); err == nil {
			t.Fatal("expected audience failure")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		bad := mustSignJWT(t, key, jwtClaims{
			Issuer: "https://evil.example", Audience: []string{testAudience},
			Expiry: now.Add(time.Minute), IssuedAt: now, NotBefore: now.Add(-time.Minute),
			Repository: "acme-corp/api", RepositoryOwner: "acme-corp",
		})
		if _, err := verifier.Verify(context.Background(), bad); err == nil {
			t.Fatal("expected issuer failure")
		}
	})

	t.Run("expired", func(t *testing.T) {
		bad := mustSignJWT(t, key, jwtClaims{
			Issuer: testIssuer, Audience: []string{testAudience},
			Expiry: now.Add(-time.Minute), IssuedAt: now.Add(-10 * time.Minute), NotBefore: now.Add(-10 * time.Minute),
			Repository: "acme-corp/api", RepositoryOwner: "acme-corp",
		})
		if _, err := verifier.Verify(context.Background(), bad); err == nil {
			t.Fatal("expected expiry failure")
		}
	})

	t.Run("nbf in future", func(t *testing.T) {
		// go-oidc allows ~5m clock skew on nbf; push beyond that leeway.
		bad := mustSignJWT(t, key, jwtClaims{
			Issuer: testIssuer, Audience: []string{testAudience},
			Expiry: now.Add(30 * time.Minute), IssuedAt: now, NotBefore: now.Add(20 * time.Minute),
			Repository: "acme-corp/api", RepositoryOwner: "acme-corp",
		})
		if _, err := verifier.Verify(context.Background(), bad); err == nil {
			t.Fatal("expected nbf failure")
		}
	})

	t.Run("not allowlisted", func(t *testing.T) {
		bad := mustSignJWT(t, key, jwtClaims{
			Issuer: testIssuer, Audience: []string{testAudience},
			Expiry: now.Add(time.Minute), IssuedAt: now, NotBefore: now.Add(-time.Minute),
			Repository: "other/repo", RepositoryOwner: "other",
		})
		if _, err := verifier.Verify(context.Background(), bad); err == nil {
			t.Fatal("expected allowlist failure")
		}
	})

	t.Run("acme-corp does not match acme-corp2", func(t *testing.T) {
		bad := mustSignJWT(t, key, jwtClaims{
			Issuer: testIssuer, Audience: []string{testAudience},
			Expiry: now.Add(time.Minute), IssuedAt: now, NotBefore: now.Add(-time.Minute),
			Repository: "acme-corp2/api", RepositoryOwner: "acme-corp2",
		})
		if _, err := verifier.Verify(context.Background(), bad); err == nil {
			t.Fatal("expected allowlist failure for acme-corp2")
		}
	})

	t.Run("repository exact match", func(t *testing.T) {
		ok := mustSignJWT(t, key, jwtClaims{
			Issuer: testIssuer, Audience: []string{testAudience},
			Expiry: now.Add(time.Minute), IssuedAt: now, NotBefore: now.Add(-time.Minute),
			Repository: "partner-org/payments", RepositoryOwner: "partner-org",
		})
		if _, err := verifier.Verify(context.Background(), ok); err != nil {
			t.Fatalf("repository match: %v", err)
		}
	})
}

func TestVerifier_FetchingKeysUnavailable(t *testing.T) {
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	t.Cleanup(jwks.Close)

	cfg := oidcauth.Config{
		Enabled:  true,
		Issuer:   testIssuer,
		Audience: testAudience,
		JWKSURL:  jwks.URL,
		Allow:    []oidcauth.AllowEntry{{RepositoryOwner: "acme-corp"}},
	}
	verifier, err := oidcauth.NewVerifier(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	key := mustRSAKey(t)
	raw := mustSignJWT(t, key, jwtClaims{
		Issuer: testIssuer, Audience: []string{testAudience},
		Expiry: time.Now().Add(time.Minute), IssuedAt: time.Now(), NotBefore: time.Now().Add(-time.Minute),
		Repository: "acme-corp/api", RepositoryOwner: "acme-corp",
	})
	_, err = verifier.Verify(context.Background(), raw)
	if err == nil {
		t.Fatal("expected fetching-keys failure")
	}
	if !errors.Is(err, oidcauth.ErrFetchingKeys) && !strings.Contains(err.Error(), "fetching keys") {
		t.Fatalf("error: got %v, want ErrFetchingKeys", err)
	}
}

func TestVerifier_FakeIssuerIntegration(t *testing.T) {
	key := mustRSAKey(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       &key.PublicKey,
				KeyID:     "test-key",
				Algorithm: string(jose.RS256),
				Use:       "sig",
			}},
		})
	}))
	t.Cleanup(jwks.Close)

	cfg := oidcauth.Config{
		Enabled:  true,
		Issuer:   testIssuer,
		Audience: testAudience,
		JWKSURL:  jwks.URL,
		Allow:    []oidcauth.AllowEntry{{Repository: "acme-corp/api"}},
	}
	verifier, err := oidcauth.NewVerifier(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	raw := mustSignJWT(t, key, jwtClaims{
		Issuer: testIssuer, Audience: []string{testAudience},
		Expiry: time.Now().Add(time.Minute), IssuedAt: time.Now(), NotBefore: time.Now().Add(-time.Minute),
		Repository: "acme-corp/api", RepositoryOwner: "acme-corp",
	})
	principal, err := verifier.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if principal.Claims.Repository != "acme-corp/api" {
		t.Fatalf("repository: got %q", principal.Claims.Repository)
	}
}

type jwtClaims struct {
	Issuer            string
	Subject           string
	Audience          []string
	Expiry            time.Time
	IssuedAt          time.Time
	NotBefore         time.Time
	Repository        string
	RepositoryOwner   string
	RepositoryID      string
	RepositoryOwnerID string
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func mustSignJWT(t *testing.T, key *rsa.PrivateKey, claims jwtClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":                 claims.Issuer,
		"sub":                 claims.Subject,
		"aud":                 claims.Audience,
		"exp":                 claims.Expiry.Unix(),
		"iat":                 claims.IssuedAt.Unix(),
		"nbf":                 claims.NotBefore.Unix(),
		"repository":          claims.Repository,
		"repository_owner":    claims.RepositoryOwner,
		"repository_id":       claims.RepositoryID,
		"repository_owner_id": claims.RepositoryOwnerID,
	})
	token.Header["kid"] = "test-key"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}
