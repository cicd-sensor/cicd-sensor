package sink

import "testing"

func TestJoinPrefix(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		key    string
		want   string
	}{
		{name: "empty prefix returns key", key: "20260518/log.json.gz", want: "20260518/log.json.gz"},
		{name: "joins prefix and key", prefix: "prod/logs", key: "20260518/log.json.gz", want: "prod/logs/20260518/log.json.gz"},
		{name: "trims prefix and key separators", prefix: "/prod/logs/", key: "/20260518/log.json.gz", want: "prod/logs/20260518/log.json.gz"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := joinPrefix(tt.prefix, tt.key); got != tt.want {
				t.Fatalf("joinPrefix: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseObjectURI(t *testing.T) {
	cases := []struct {
		name       string
		scheme     string
		uri        string
		wantBucket string
		wantPrefix string
		wantError  bool
	}{
		{
			name:       "gcs uri splits bucket and prefix",
			scheme:     "gs",
			uri:        "gs://logs/prod/logs",
			wantBucket: "logs",
			wantPrefix: "prod/logs",
		},
		{
			name:       "s3 uri splits bucket and prefix",
			scheme:     "s3",
			uri:        "s3://logs/prod/logs",
			wantBucket: "logs",
			wantPrefix: "prod/logs",
		},
		{
			name:       "trailing slash is trimmed from prefix",
			scheme:     "gs",
			uri:        "gs://logs/prod/",
			wantBucket: "logs",
			wantPrefix: "prod",
		},
		{
			name:       "uri without prefix returns empty prefix",
			scheme:     "gs",
			uri:        "gs://logs",
			wantBucket: "logs",
			wantPrefix: "",
		},
		{
			name:      "empty uri is rejected",
			scheme:    "gs",
			uri:       "",
			wantError: true,
		},
		{
			name:      "wrong uri scheme is rejected",
			scheme:    "gs",
			uri:       "s3://logs/prod",
			wantError: true,
		},
		{
			name:      "uri query is rejected",
			scheme:    "gs",
			uri:       "gs://logs/prod?x=1",
			wantError: true,
		},
		{
			name:      "uri fragment is rejected",
			scheme:    "gs",
			uri:       "gs://logs/prod#frag",
			wantError: true,
		},
		{
			name:      "uri without bucket is rejected",
			scheme:    "gs",
			uri:       "gs:///prod",
			wantError: true,
		},
		{
			name:      "plain bucket name without scheme is rejected",
			scheme:    "gs",
			uri:       "logs/prod",
			wantError: true,
		},
		{
			name:      "parent traversal segment is rejected",
			scheme:    "gs",
			uri:       "gs://logs/../etc/passwd",
			wantError: true,
		},
		{
			name:      "nested parent traversal segment is rejected",
			scheme:    "gs",
			uri:       "gs://logs/prod/../escape",
			wantError: true,
		},
		{
			name:      "current dir segment is rejected",
			scheme:    "gs",
			uri:       "gs://logs/./prod",
			wantError: true,
		},
		{
			name:      "consecutive slashes produce empty segment and are rejected",
			scheme:    "gs",
			uri:       "gs://logs/prod//logs",
			wantError: true,
		},
		{
			name:      "invalid utf8 prefix is rejected",
			scheme:    "gs",
			uri:       "gs://logs/" + string([]byte{0xff, 0xfe}),
			wantError: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			gotBucket, gotPrefix, err := parseObjectURI(tt.scheme, tt.uri)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseObjectURI: %v", err)
			}
			if gotBucket != tt.wantBucket {
				t.Fatalf("bucket: got %q, want %q", gotBucket, tt.wantBucket)
			}
			if gotPrefix != tt.wantPrefix {
				t.Fatalf("prefix: got %q, want %q", gotPrefix, tt.wantPrefix)
			}
		})
	}
}
