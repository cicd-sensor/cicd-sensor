package kerneltracker

import "testing"

// TestHTTPSourceValue locks the ABI source tag -> rule-facing string mapping,
// including the openssl tag (only exercised by privileged integration tests
// otherwise) and the unknown-value path that drops a skewed sample.
func TestHTTPSourceValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source HTTPSource
		want   string
		wantOK bool
	}{
		{"cleartext tag maps to its rule string", HTTPSourceCleartext, "cleartext_http", true},
		{"openssl tag maps to its rule string", HTTPSourceOpenSSL, "openssl", true},
		{"nghttp2 tag maps to its rule string", HTTPSourceNghttp2, "nghttp2", true},
		{"Go net/http tag maps to its rule string", HTTPSourceGoNetHTTP, "go_net_http", true},
		{"unknown tag is rejected as kernel/userspace skew", HTTPSource(200), "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := httpSourceValue(tt.source)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("httpSourceValue(%d) = (%q, %v), want (%q, %v)",
					tt.source, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
