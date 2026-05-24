package sink

import (
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

func TestObjectKey(t *testing.T) {
	batch := objectKeyTestBatch()

	got, err := objectKey(batch)
	if err != nil {
		t.Fatalf("objectKey: %v", err)
	}
	pattern := `^detection_log/dt=2026-04-26/hour=07/20260426073045123_github-github-com-acme-example-123-build-1-a28bbc96-b9a8d436bdb471f3_host_[0-9a-f]{8}\.json\.gz$`
	if !regexp.MustCompile(pattern).MatchString(got) {
		t.Fatalf("key: got %q, want pattern %s", got, pattern)
	}
}

func TestObjectKey_RandomSuffixIsLastSegment(t *testing.T) {
	first := objectKeyTestBatch()

	firstKey, err := objectKey(first)
	if err != nil {
		t.Fatalf("first objectKey: %v", err)
	}
	secondKey, err := objectKey(first)
	if err != nil {
		t.Fatalf("second objectKey: %v", err)
	}
	if firstKey == secondKey {
		t.Fatalf("same batch produced duplicate object key: %q", firstKey)
	}
	prefix := "detection_log/dt=2026-04-26/hour=07/20260426073045123_github-github-com-acme-example-123-build-1-a28bbc96-b9a8d436bdb471f3_host_"
	for _, key := range []string{firstKey, secondKey} {
		if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, ".json.gz") {
			t.Fatalf("random suffix is not the final key segment: %q", key)
		}
	}
}

func TestObjectKeySuffix(t *testing.T) {
	got, err := objectKeySuffix()
	if err != nil {
		t.Fatalf("objectKeySuffix: %v", err)
	}
	if len(got) != 8 {
		t.Fatalf("suffix length: got %d, want 8 (%q)", len(got), got)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("suffix is not hex: %q", got)
	}
}

func TestPubSubAttributes(t *testing.T) {
	got := pubsubAttributes(objectKeyTestBatch())

	if _, ok := got["object_key"]; ok {
		t.Fatalf("object_key attribute should not be emitted: %+v", got)
	}
	want := map[string]string{
		"content_type": "application/json",
		"flush_at":     "20260426073045123",
		"log_type":     string(logtype.Detection),
		"scope":        string(ScopeHost),
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("attribute %s: got %q, want %q", key, got[key], value)
		}
	}
	if _, ok := got["content_encoding"]; ok {
		t.Fatalf("content_encoding attribute should not be emitted: %+v", got)
	}
}

func TestFormatFlushAt(t *testing.T) {
	tests := []struct {
		name  string
		value time.Time
		want  string
	}{
		{
			name:  "formats millisecond precision",
			value: time.Date(2026, 4, 26, 7, 30, 45, 123_000_000, time.UTC),
			want:  "20260426073045123",
		},
		{
			name:  "truncates sub-millisecond precision",
			value: time.Date(2026, 4, 26, 7, 30, 45, 999_999_999, time.UTC),
			want:  "20260426073045999",
		},
		{
			name:  "zero pads missing milliseconds",
			value: time.Date(2026, 4, 26, 7, 30, 45, 0, time.UTC),
			want:  "20260426073045000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatFlushAt(tt.value); got != tt.want {
				t.Fatalf("formatFlushAt: got %q, want %q", got, tt.want)
			}
		})
	}
}

func objectKeyTestBatch() IngestLogBatch {
	return IngestLogBatch{
		LogType: logtype.Detection,
		Identity: jobcontext.GitHubJobIdentity(
			"github.com",
			"acme/example",
			"123",
			"build",
			"1",
			"runner-1",
		),
		Scope:      ScopeHost,
		FlushAt:    time.Date(2026, 4, 26, 7, 30, 45, 123_000_000, time.UTC),
		ReceivedAt: time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC),
		Body:       []byte{0x1f, 0x8b},
	}
}
