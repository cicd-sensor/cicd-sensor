package oidc

import "strings"

// Claims are the GitHub Actions OIDC claims used for allowlisting and binding.
type Claims struct {
	Repository        string
	RepositoryOwner   string
	RepositoryID      string
	RepositoryOwnerID string
	Ref               string
	EventName         string
}

// Match reports whether any allowlist entry exactly matches the claims.
func Match(allow []AllowEntry, claims Claims) (AllowEntry, bool) {
	for _, entry := range allow {
		if entryMatches(entry, claims) {
			return entry, true
		}
	}
	return AllowEntry{}, false
}

func entryMatches(entry AllowEntry, claims Claims) bool {
	if entry.RepositoryOwner != "" && entry.RepositoryOwner != claims.RepositoryOwner {
		return false
	}
	if entry.Repository != "" && entry.Repository != claims.Repository {
		return false
	}
	if entry.RepositoryOwnerID != "" && entry.RepositoryOwnerID != claims.RepositoryOwnerID {
		return false
	}
	if entry.RepositoryID != "" && entry.RepositoryID != claims.RepositoryID {
		return false
	}
	return true
}

// NormalizeRepository lowercases a GitHub repository path for binding compares.
func NormalizeRepository(repo string) string {
	return strings.ToLower(strings.TrimSpace(repo))
}
