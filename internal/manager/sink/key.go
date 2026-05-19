package sink

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

func joinPrefix(prefix, key string) string {
	// Constructors normalize prefixes first; this stays defensive because
	// tests and future sinks can still call joinPrefix directly.
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return key
	}
	return prefix + "/" + strings.TrimLeft(key, "/")
}

func normalizeObjectLocation(scheme, bucket, prefix string) (string, string, error) {
	if bucket == "" {
		return "", "", fmt.Errorf("%s bucket is required", scheme)
	}
	if strings.Contains(bucket, "://") {
		if prefix != "" {
			return "", "", fmt.Errorf("prefix must be empty when bucket is a %s:// URI", scheme)
		}
		u, err := url.Parse(bucket)
		if err != nil {
			return "", "", fmt.Errorf("parse %s URI: %w", scheme, err)
		}
		if u.Scheme != scheme {
			return "", "", fmt.Errorf("bucket URI must use %s:// scheme", scheme)
		}
		if u.Host == "" {
			return "", "", fmt.Errorf("%s URI must include a bucket name", scheme)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return "", "", fmt.Errorf("%s URI must not include query or fragment", scheme)
		}
		bucket = u.Host
		prefix = strings.TrimPrefix(u.Path, "/")
	}
	if strings.Contains(bucket, "/") || strings.Contains(bucket, "\\") {
		return "", "", fmt.Errorf("bucket must be a bucket name, not a path")
	}
	normalizedPrefix, err := normalizeObjectPrefix(prefix)
	if err != nil {
		return "", "", err
	}
	return bucket, normalizedPrefix, nil
}

func normalizeObjectPrefix(prefix string) (string, error) {
	if strings.Contains(prefix, "\\") {
		return "", errors.New("prefix must use forward slash separators")
	}
	return strings.Trim(prefix, "/"), nil
}
