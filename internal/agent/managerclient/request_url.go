package managerclient

import (
	"fmt"
	"net/url"
	"strings"
)

// DefaultIDTokenRequestURLHosts is the Agent startup allowlist default for
// ACTIONS_ID_TOKEN_REQUEST_URL hosts. Measurement item 5 may refine this.
var DefaultIDTokenRequestURLHosts = []string{"*.actions.githubusercontent.com"}

// ValidateIDTokenRequestURL checks scheme https and host against the Agent
// startup allowlist. The allowlist is never widened via project start.
func ValidateIDTokenRequestURL(raw string, allowedHosts []string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("request_url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse request_url: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("request_url must use https")
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("request_url must include a host")
	}
	if len(allowedHosts) == 0 {
		allowedHosts = DefaultIDTokenRequestURLHosts
	}
	if !hostAllowed(host, allowedHosts) {
		return fmt.Errorf("request_url host %q is not allowlisted", host)
	}
	return nil
}

func hostAllowed(host string, patterns []string) bool {
	host = strings.ToLower(host)
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if host == strings.TrimPrefix(pattern, "*.") || strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if host == pattern {
			return true
		}
	}
	return false
}
