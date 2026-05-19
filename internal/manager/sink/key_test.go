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

func TestNormalizeObjectLocation(t *testing.T) {
	cases := []struct {
		name       string
		scheme     string
		bucket     string
		prefix     string
		wantBucket string
		wantPrefix string
		wantError  bool
	}{
		{
			name:       "bucket and prefix are kept separate",
			scheme:     "gs",
			bucket:     "logs",
			prefix:     "prod/logs",
			wantBucket: "logs",
			wantPrefix: "prod/logs",
		},
		{
			name:       "trailing and leading slashes are normalized",
			scheme:     "gs",
			bucket:     "logs",
			prefix:     "/prod/",
			wantBucket: "logs",
			wantPrefix: "prod",
		},
		{
			name:       "gcs uri splits bucket and prefix",
			scheme:     "gs",
			bucket:     "gs://logs/prod/logs",
			wantBucket: "logs",
			wantPrefix: "prod/logs",
		},
		{
			name:       "s3 uri splits bucket and prefix",
			scheme:     "s3",
			bucket:     "s3://logs/prod/logs",
			wantBucket: "logs",
			wantPrefix: "prod/logs",
		},
		{
			name:      "uri and explicit prefix is ambiguous",
			scheme:    "gs",
			bucket:    "gs://logs/prod",
			prefix:    "other",
			wantError: true,
		},
		{
			name:      "wrong uri scheme is rejected",
			scheme:    "gs",
			bucket:    "s3://logs/prod",
			wantError: true,
		},
		{
			name:      "uri query is rejected",
			scheme:    "gs",
			bucket:    "gs://logs/prod?x=1",
			wantError: true,
		},
		{
			name:      "uri fragment is rejected",
			scheme:    "gs",
			bucket:    "gs://logs/prod#frag",
			wantError: true,
		},
		{
			name:      "uri without bucket is rejected",
			scheme:    "gs",
			bucket:    "gs:///prod",
			wantError: true,
		},
		{
			name:      "bucket path without uri is rejected",
			scheme:    "gs",
			bucket:    "logs/prod",
			wantError: true,
		},
		{
			name:      "backslash bucket is rejected",
			scheme:    "gs",
			bucket:    `logs\prod`,
			wantError: true,
		},
		{
			name:      "backslash prefix is rejected",
			scheme:    "gs",
			bucket:    "logs",
			prefix:    `prod\logs`,
			wantError: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			gotBucket, gotPrefix, err := normalizeObjectLocation(tt.scheme, tt.bucket, tt.prefix)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeObjectLocation: %v", err)
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
