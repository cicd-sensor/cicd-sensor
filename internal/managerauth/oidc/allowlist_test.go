package oidc

import (
	"strings"
	"testing"
)

func TestAllowEntryFromOptional_OmitVsExplicitEmpty(t *testing.T) {
	owner := "acme-corp"
	empty := ""
	ws := "   "
	repo := "acme-corp/api"

	t.Run("omitted repository unconstrained", func(t *testing.T) {
		entry, err := AllowEntryFromOptional(&owner, nil, nil, nil)
		if err != nil {
			t.Fatalf("AllowEntryFromOptional: %v", err)
		}
		if entry.RepositoryOwner != owner || entry.Repository != "" {
			t.Fatalf("entry: %+v", entry)
		}
		if err := entry.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		claims := Claims{RepositoryOwner: "acme-corp", Repository: "acme-corp/other"}
		if _, ok := Match([]AllowEntry{entry}, claims); !ok {
			t.Fatal("omitted repository must not constrain match")
		}
	})

	t.Run("explicit empty repository rejected", func(t *testing.T) {
		_, err := AllowEntryFromOptional(&owner, &empty, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "repository must not be empty") {
			t.Fatalf("got %v, want explicit empty rejection", err)
		}
	})

	t.Run("explicit whitespace repository rejected", func(t *testing.T) {
		_, err := AllowEntryFromOptional(&owner, &ws, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "repository must not be empty") {
			t.Fatalf("got %v, want whitespace rejection", err)
		}
	})

	t.Run("present repository constrains", func(t *testing.T) {
		entry, err := AllowEntryFromOptional(&owner, &repo, nil, nil)
		if err != nil {
			t.Fatalf("AllowEntryFromOptional: %v", err)
		}
		if _, ok := Match([]AllowEntry{entry}, Claims{RepositoryOwner: owner, Repository: repo}); !ok {
			t.Fatal("expected match")
		}
		if _, ok := Match([]AllowEntry{entry}, Claims{RepositoryOwner: owner, Repository: "acme-corp/other"}); ok {
			t.Fatal("present repository must constrain match")
		}
	})
}

func TestAllowEntryValidate(t *testing.T) {
	tests := []struct {
		name    string
		entry   AllowEntry
		wantErr string
	}{
		{
			name:  "repository_owner ok",
			entry: AllowEntry{RepositoryOwner: "acme-corp"},
		},
		{
			name:  "repository ok",
			entry: AllowEntry{Repository: "partner-org/payments"},
		},
		{
			name:  "owner with id pin ok",
			entry: AllowEntry{RepositoryOwner: "acme-corp", RepositoryOwnerID: "123456"},
		},
		{
			name:    "empty entry",
			entry:   AllowEntry{},
			wantErr: "at least one known claim key",
		},
		{
			name:    "id only",
			entry:   AllowEntry{RepositoryOwnerID: "123"},
			wantErr: "repository_owner or repository",
		},
		{
			name:    "owner with slash",
			entry:   AllowEntry{RepositoryOwner: "acme/corp"},
			wantErr: "must not contain '/'",
		},
		{
			name:    "repository without slash",
			entry:   AllowEntry{Repository: "payments"},
			wantErr: "owner/name",
		},
		{
			name:    "whitespace owner",
			entry:   AllowEntry{RepositoryOwner: "  "},
			wantErr: "at least one known claim key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entry.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate: got %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	valid := Config{
		Enabled:  true,
		Issuer:   "https://token.actions.githubusercontent.com",
		Audience: "https://manager.example.com",
		JWKSURL:  "https://token.actions.githubusercontent.com/.well-known/jwks",
		Allow:    []AllowEntry{{RepositoryOwner: "acme-corp"}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if err := (Config{Enabled: false}).Validate(); err != nil {
		t.Fatalf("disabled config: %v", err)
	}

	missingAllow := valid
	missingAllow.Allow = nil
	if err := missingAllow.Validate(); err == nil || !strings.Contains(err.Error(), "allow must be non-empty") {
		t.Fatalf("missing allow: got %v", err)
	}
}

func TestMatchExactClaims(t *testing.T) {
	allow := []AllowEntry{
		{RepositoryOwner: "acme-corp"},
		{Repository: "partner-org/payments"},
	}
	claims := Claims{RepositoryOwner: "acme-corp", Repository: "acme-corp/api"}
	if _, ok := Match(allow, claims); !ok {
		t.Fatal("expected repository_owner match")
	}

	// Exact match: acme-corp must not admit acme-corp2.
	claims2 := Claims{RepositoryOwner: "acme-corp2", Repository: "acme-corp2/api"}
	if _, ok := Match(allow, claims2); ok {
		t.Fatal("acme-corp must not match acme-corp2")
	}

	repoClaims := Claims{RepositoryOwner: "partner-org", Repository: "partner-org/payments"}
	if _, ok := Match(allow, repoClaims); !ok {
		t.Fatal("expected repository match")
	}

	pin := []AllowEntry{{RepositoryOwner: "acme-corp", RepositoryOwnerID: "123"}}
	if _, ok := Match(pin, Claims{RepositoryOwner: "acme-corp", RepositoryOwnerID: "999"}); ok {
		t.Fatal("id pin must reject renamed/recreated owner")
	}
	if _, ok := Match(pin, Claims{RepositoryOwner: "acme-corp", RepositoryOwnerID: "123"}); !ok {
		t.Fatal("id pin must accept matching owner id")
	}
}
