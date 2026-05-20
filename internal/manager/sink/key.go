package sink

import (
	"fmt"
	"io/fs"
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

// formatObjectURI is the inverse of parseObjectURI: it composes a
// scheme://bucket/prefix string from already-validated components. The prefix
// may be empty.
func formatObjectURI(scheme, bucket, prefix string) string {
	if prefix == "" {
		return scheme + "://" + bucket
	}
	return scheme + "://" + bucket + "/" + prefix
}

// parseObjectURI splits an object storage URI like gs://bucket/prefix/path/
// into its bucket and prefix components. The prefix may be empty. The prefix
// is validated with fs.ValidPath to reject traversal segments (".", "..",
// empty) so downstream consumers that mirror keys onto a filesystem cannot
// be tricked into escaping their root directory.
func parseObjectURI(scheme, uri string) (string, string, error) {
	if uri == "" {
		return "", "", fmt.Errorf("%s uri is required", scheme)
	}
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", fmt.Errorf("parse %s uri: %w", scheme, err)
	}
	if u.Scheme != scheme {
		return "", "", fmt.Errorf("uri must use %s:// scheme", scheme)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("%s uri must include a bucket name", scheme)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("%s uri must not include query or fragment", scheme)
	}
	prefix := strings.Trim(u.Path, "/")
	if prefix != "" && !fs.ValidPath(prefix) {
		return "", "", fmt.Errorf("%s uri prefix %q is invalid: must be UTF-8 and contain no \".\", \"..\", or empty path segments", scheme, prefix)
	}
	return u.Host, prefix, nil
}
