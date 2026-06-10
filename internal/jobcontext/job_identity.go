// Package jobcontext defines shared CI job identity, provider, and scope types.
package jobcontext

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// JobIdentity identifies one CI job execution.
type JobIdentity struct {
	Provider     Provider `json:"provider"`
	ProviderHost string   `json:"provider_host"`
	ProjectPath  string   `json:"project_path"`

	// GitHub
	GitHubRunID            string `json:"github_run_id,omitempty"`
	GitHubJob              string `json:"github_job,omitempty"`
	GitHubRunAttempt       string `json:"github_run_attempt,omitempty"`
	GitHubRunnerTrackingID string `json:"github_runner_tracking_id,omitempty"`

	// GitLab
	GitLabJobID string `json:"gitlab_job_id,omitempty"`
}

// GitHubJobIdentity builds a GitHub job identity from raw provider fields.
func GitHubJobIdentity(providerHost, projectPath, runID, job, runAttempt, runnerTrackingID string) JobIdentity {
	return JobIdentity{
		Provider:               ProviderGitHub,
		ProviderHost:           providerHost,
		ProjectPath:            projectPath,
		GitHubRunID:            runID,
		GitHubJob:              job,
		GitHubRunAttempt:       runAttempt,
		GitHubRunnerTrackingID: runnerTrackingID,
	}
}

// GitLabJobIdentity builds a GitLab job identity from raw provider fields.
func GitLabJobIdentity(providerHost, projectPath, jobID string) JobIdentity {
	return JobIdentity{
		Provider:     ProviderGitLab,
		ProviderHost: providerHost,
		ProjectPath:  projectPath,
		GitLabJobID:  jobID,
	}
}

// DeriveProviderHost normalizes a raw CI-provider URL into provider_host.
func DeriveProviderHost(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", rawURL, err)
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimRight(host, ".")
	if host == "" {
		return "", fmt.Errorf("no host in %q", rawURL)
	}
	return host, nil
}

// Validate checks that the identity contains the minimum provider-specific fields.
func (j JobIdentity) Validate() error {
	if j.Provider == "" {
		return errors.New("provider is required")
	}
	if j.ProviderHost == "" {
		return errors.New("provider_host is required")
	}
	if j.ProjectPath == "" {
		return errors.New("project_path is required")
	}
	if err := validateIdentityFieldLen("provider_host", j.ProviderHost, maxIdentityFieldLen); err != nil {
		return err
	}
	if err := validateIdentityFieldLen("project_path", j.ProjectPath, maxIdentityFieldLen); err != nil {
		return err
	}

	switch j.Provider {
	case ProviderGitHub:
		if j.GitHubRunID == "" || j.GitHubJob == "" || j.GitHubRunAttempt == "" || j.GitHubRunnerTrackingID == "" {
			return errors.New("github_run_id, github_job, github_run_attempt, and github_runner_tracking_id are required for github")
		}
		if err := validateIdentityFieldLen("github_run_id", j.GitHubRunID, maxIdentityFieldLen); err != nil {
			return err
		}
		if err := validateIdentityFieldLen("github_job", j.GitHubJob, maxIdentityFieldLen); err != nil {
			return err
		}
		if err := validateIdentityFieldLen("github_run_attempt", j.GitHubRunAttempt, maxIdentityFieldLen); err != nil {
			return err
		}
		if j.GitLabJobID != "" {
			return errors.New("gitlab_job_id must be empty for github")
		}
		if !isPositiveIntString(j.GitHubRunID) {
			return errors.New("github_run_id must be a positive integer")
		}
		if !isPositiveIntString(j.GitHubRunAttempt) {
			return errors.New("github_run_attempt must be a positive integer")
		}
		if len(j.GitHubRunnerTrackingID) > maxTrackingIDLen {
			return fmt.Errorf("github_runner_tracking_id exceeds %d bytes", maxTrackingIDLen)
		}
	case ProviderGitLab:
		if j.GitLabJobID == "" {
			return errors.New("gitlab_job_id is required for gitlab")
		}
		if err := validateIdentityFieldLen("gitlab_job_id", j.GitLabJobID, maxIdentityFieldLen); err != nil {
			return err
		}
		if j.GitHubRunID != "" || j.GitHubJob != "" || j.GitHubRunAttempt != "" || j.GitHubRunnerTrackingID != "" {
			return errors.New("github fields must be empty for gitlab")
		}
		if !isPositiveIntString(j.GitLabJobID) {
			return errors.New("gitlab_job_id must be a positive integer")
		}
	default:
		return fmt.Errorf("unsupported provider: %s", j.Provider)
	}

	return nil
}

const (
	// maxIdentityFieldLen bounds malformed caller-provided identity strings
	// before they become log fields or Job map keys.
	maxIdentityFieldLen = 2048
	// maxTrackingIDLen bounds malformed runner tracking IDs.
	maxTrackingIDLen = 128
)

func validateIdentityFieldLen(name, value string, maxLen int) error {
	if len(value) > maxLen {
		return fmt.Errorf("%s exceeds %d bytes", name, maxLen)
	}
	return nil
}

// isPositiveIntString reports whether s is a decimal positive integer.
func isPositiveIntString(s string) bool {
	if s == "" {
		return false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0
}

const (
	pathKeySegmentMaxBytes   = 64
	pathKeyHashBytes         = 4
	pathKeyIdentityHashBytes = 8
)

// FilenameKey returns a deterministic, filename-safe job slug.
func (j JobIdentity) FilenameKey() (string, error) {
	if err := j.Validate(); err != nil {
		return "", err
	}
	parts := canonicalPathKeyParts(j)
	canonical := strings.Join(parts, "\x00")
	for i, part := range parts {
		parts[i] = sanitizePathKeySegment(part)
	}
	return strings.Join(parts, "-") + "-" + hash16(canonical), nil
}

func sanitizePathKeySegment(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}

	out := strings.Trim(b.String(), "-")
	if out == "" {
		return hash8(s)
	}
	if len(out) <= pathKeySegmentMaxBytes {
		return out
	}
	return capPathKeySegment(out, s)
}

func capPathKeySegment(s, original string) string {
	hash := hash8(original)
	prefixLen := pathKeySegmentMaxBytes - 1 - len(hash)
	prefix := strings.TrimRight(s[:prefixLen], "-")
	if prefix == "" {
		return hash
	}
	return prefix + "-" + hash
}

func canonicalPathKeyParts(j JobIdentity) []string {
	return []string{
		string(j.Provider),
		j.ProviderHost,
		j.ProjectPath,
		compactJobRef(j),
	}
}

func compactJobRef(identity JobIdentity) string {
	switch identity.Provider {
	case ProviderGitHub:
		return fmt.Sprintf(
			"%s_%s_%s_%s",
			identity.GitHubRunID,
			identity.GitHubJob,
			identity.GitHubRunAttempt,
			trackingHash8(identity.GitHubRunnerTrackingID),
		)
	case ProviderGitLab:
		return identity.GitLabJobID
	default:
		return ""
	}
}

func trackingHash8(s string) string {
	if s == "" {
		return ""
	}
	return hashHex(s, pathKeyHashBytes)
}

func hash8(s string) string {
	return hashHex(s, pathKeyHashBytes)
}

func hash16(s string) string {
	return hashHex(s, pathKeyIdentityHashBytes)
}

func hashHex(s string, n int) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:n])
}
