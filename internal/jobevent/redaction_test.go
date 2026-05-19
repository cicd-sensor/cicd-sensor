package jobevent

import (
	"slices"
	"strings"
	"testing"
)

func TestRedactArgvForOutput_Table(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		argv []string
		want []string
	}{
		{name: "nil argv", argv: nil, want: nil},
		{name: "empty slice", argv: []string{}, want: []string{}},
		{name: "empty element", argv: []string{""}, want: []string{""}},
		{name: "short verbatim", argv: []string{"echo"}, want: []string{"echo"}},
		{name: "12 bytes boundary", argv: []string{"abcdef012345"}, want: []string{"abcdef012345"}},
		{
			name: "13 bytes truncated",
			argv: []string{"abcdef0123456"},
			want: []string{"abcdef012345<truncated, 13 bytes>"},
		},
		{
			name: "long lowercase path truncated, not redacted",
			argv: []string{"/tmp/example/file/path/longer/than/sixteen"},
			want: []string{"/tmp/example<truncated, 42 bytes>"},
		},
		{
			name: "lower+digit only, truncated",
			argv: []string{"abcdef0123456789xyz"},
			want: []string{"abcdef012345<truncated, 19 bytes>"},
		},
		{
			name: "3 classes, no signal: truncated",
			argv: []string{"aBcDeF0123456789xYz"},
			want: []string{"aBcDeF012345<truncated, 19 bytes>"},
		},
		{
			name: "hyphens-only",
			argv: []string{"------------------------"},
			want: []string{"------------<truncated, 24 bytes>"},
		},
		{
			name: "prev --token redacts value",
			argv: []string{"--token", "aBcDeF0123456789xYz"},
			want: []string{"<redacted>", "<redacted>"},
		},
		{
			name: "prev --password via --pass prefix",
			argv: []string{"--password", "aBcDeF0123456789xYz"},
			want: []string{"<redacted>", "<redacted>"},
		},
		{
			name: "prev --api-key via --api prefix",
			argv: []string{"--api-key", "aBcDeF0123456789xYz"},
			want: []string{"<redacted>", "<redacted>"},
		},
		{
			name: "prev --keystore via --key prefix",
			argv: []string{"--keystore", "aBcDeF0123456789xYz"},
			want: []string{"<redacted>", "<redacted>"},
		},
		{
			name: "mysql -p redacts the next value",
			argv: []string{"mysql", "-p", "aBcDeF0123456789xYz", "-u", "root"},
			want: []string{"mysql", "-p", "<redacted>", "-u", "root"},
		},
		{
			name: "weak password after --password is redacted",
			argv: []string{"--password", "weakpw"},
			want: []string{"<redacted>", "<redacted>"},
		},
		{
			name: "lowercase value after --token is redacted",
			argv: []string{"--token", "alllowercasevaluevalue"},
			want: []string{"<redacted>", "<redacted>"},
		},
		{
			name: "prefix match also redacts the next arg",
			argv: []string{"--token=aBc1", "Unrelated123Arg"},
			want: []string{"<redacted>", "<redacted>"},
		},
		{
			name: "long flag containing credential keyword is redacted",
			argv: []string{"--api-secret-key-abcd"},
			want: []string{"<redacted>"},
		},
		{
			name: "inline --token=VALUE form",
			argv: []string{"curl", "--token=aBcDeF0123456789xYz", "https://api.example.com"},
			want: []string{"curl", "<redacted>", "<redacted>"},
		},
		{
			name: "Authorization header inside bash -c blob",
			argv: []string{"bash", "-c", "curl -H \"Authorization: Bearer aBc123XYZdef\" https://api.example.com"},
			want: []string{"bash", "-c", "<redacted>"},
		},
		{
			name: "curl -H redacts opaque cookie value",
			argv: []string{"curl", "-H", "Cookie: session=aB1cD2eF3gH"},
			want: []string{"curl", "-H", "<redacted>"},
		},
		{
			name: "Bearer header value alone",
			argv: []string{"-H", "Bearer aBc123XYZdef456"},
			want: []string{"-H", "<redacted>"},
		},
		{
			name: "AUTHORIZATION uppercase",
			argv: []string{"--header", "AUTHORIZATION: Basic dXNlcjpwYXNzd29yZA=="},
			want: []string{"--header", "<redacted>"},
		},
		{name: "AWS AKIA", argv: []string{"echo", "AKIA1234567890ABCDEF"}, want: []string{"echo", "<redacted>"}},
		{name: "GitHub ghp_", argv: []string{"echo", "ghp_abcDEF1234567890XYZqrstUVWxyz"}, want: []string{"echo", "<redacted>"}},
		{name: "GitLab glpat-", argv: []string{"echo", "glpat-AbCdEf1234567890XyZ"}, want: []string{"echo", "<redacted>"}},
		{
			name: "first item carries token substring",
			argv: []string{"--token=aBcDeF0123456789secret"},
			want: []string{"<redacted>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := RedactArgvForOutput(tt.argv)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("RedactArgvForOutput(%#v):\n got: %#v\nwant: %#v", tt.argv, got, tt.want)
			}
		})
	}
}

func BenchmarkRedactArgvForOutput(b *testing.B) {
	item := strings.Repeat("aBc123-", 150)
	argv := make([]string, 0, 1+8+16*8)
	argv = append(argv, "/usr/bin/example-binary")
	for range 8 {
		argv = append(argv, item)
	}
	for range 16 * 8 {
		argv = append(argv, item)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = RedactArgvForOutput(argv)
	}
}

func TestRedactArgvForOutput_LongTruncatedNeverLeaksTail(t *testing.T) {
	t.Parallel()

	tail := "tail-bytes-must-not-leak-AaBbCc11"
	input := strings.Repeat("a", 200) + tail

	got := RedactArgvForOutput([]string{input})
	if len(got) != 1 {
		t.Fatalf("output length: got %d, want 1", len(got))
	}
	if strings.Contains(got[0], tail) {
		t.Fatalf("trailing bytes leaked: %q", got[0])
	}
	if !strings.Contains(got[0], "<truncated,") {
		t.Fatalf("expected truncation marker, got %q", got[0])
	}
}

func TestRedactProcessSummaryForOutputKeepsProcessIdentity(t *testing.T) {
	t.Parallel()

	got := RedactProcessSummaryForOutput(ProcessSummary{
		PID:           101,
		StartBoottime: 202,
		ExecPath:      "/usr/bin/curl",
		Argv:          []string{"curl", "--token=secret"},
	})

	if got.PID != 101 || got.StartBoottime != 202 {
		t.Fatalf("identity: got pid=%d start_boottime=%d", got.PID, got.StartBoottime)
	}
	if got.Argv[1] != "<redacted>" {
		t.Fatalf("argv[1] = %q, want redacted", got.Argv[1])
	}
}

func TestContainsTokenSubstring(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		want bool
	}{
		{name: "empty", s: "", want: false},
		{name: "ordinary path", s: "/usr/bin/curl", want: false},
		{name: "generic keyword: token", s: "--token=abc", want: true},
		{name: "auth header: Bearer with space", s: "Bearer abc", want: true},
		{name: "auth header: Bearer alone", s: "Bearer", want: false},
		{name: "AWS AKIA", s: "AKIA1234567890ABCDEF", want: true},
		{name: "GitHub ghp_", s: "ghp_abcdef123", want: true},
		{name: "GitLab glpat-", s: "glpat-abc123", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := containsTokenSubstring(tt.s); got != tt.want {
				t.Fatalf("containsTokenSubstring(%q): got %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestMatchesTokenFlagPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		prev string
		want bool
	}{
		{name: "empty", prev: "", want: false},
		{name: "--token exact", prev: "--token", want: true},
		{name: "--token=value", prev: "--token=foo", want: true},
		{name: "--password via --pass", prev: "--password", want: true},
		{name: "--passphrase via --pass", prev: "--passphrase", want: true},
		{name: "--api-key via --api", prev: "--api-key", want: true},
		{name: "--apikey via --api", prev: "--apikey", want: true},
		{name: "--keystore via --key", prev: "--keystore", want: true},
		{name: "mysql -p", prev: "-p", want: true},
		{name: "find -print FP via -p", prev: "-print", want: true},
		{name: "--output not matched", prev: "--output", want: false},
		{name: "non-flag arg", prev: "value", want: false},
		{name: "curl -H", prev: "-H", want: true},
		{name: "curl --header", prev: "--header", want: true},
		{name: "short -t", prev: "-t", want: true},
		{name: "find -test FP via -t", prev: "-test", want: true},
		{name: "-Host FP via -H", prev: "-Host", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := matchesTokenFlagPrefix(tt.prev); got != tt.want {
				t.Fatalf("matchesTokenFlagPrefix(%q): got %v, want %v", tt.prev, got, tt.want)
			}
		})
	}
}
