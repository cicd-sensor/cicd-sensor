package managerclient

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
)

func TestBuildCollectorIngestLogBatch_CompressesJSONLAndPreservesFlushAt(t *testing.T) {
	flushAt := time.Date(2026, 4, 27, 12, 30, 45, 123_000_000, time.UTC)
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	batch, err := BuildCollectorIngestLogBatch(LogBatch{
		Identity: identity,
		Scope:    managerv1.Scope_SCOPE_HOST,
		Type:     managerv1.LogType_LOG_TYPE_DETECTION,
		Records:  [][]byte{[]byte(`{"rule_id":"a"}`), []byte(`{"rule_id":"b"}`)},
		FlushAt:  flushAt,
	})
	if err != nil {
		t.Fatalf("build batch: %v", err)
	}
	if got := batch.FlushAt.AsTime(); !got.Equal(flushAt) {
		t.Fatalf("flush_at: got %s, want %s", got, flushAt)
	}
	if got := batch.GetScope(); got != managerv1.Scope_SCOPE_HOST {
		t.Fatalf("scope: got %v, want %v", got, managerv1.Scope_SCOPE_HOST)
	}
	if got := batch.GetLogType(); got != managerv1.LogType_LOG_TYPE_DETECTION {
		t.Fatalf("log_type: got %v, want %v", got, managerv1.LogType_LOG_TYPE_DETECTION)
	}
	if got := batch.GetJobIdentity(); got.GetProviderHost() != identity.ProviderHost ||
		got.GetProjectPath() != identity.ProjectPath ||
		got.GetGithubRunId() != identity.GitHubRunID ||
		got.GetGithubJob() != identity.GitHubJob ||
		got.GetGithubRunAttempt() != identity.GitHubRunAttempt ||
		got.GetGithubRunnerTrackingId() != identity.GitHubRunnerTrackingID {
		t.Fatalf("job_identity mismatch: %+v", got)
	}
	if !bytes.Equal(batch.CompressedJsonl[:2], []byte{0x1f, 0x8b}) {
		t.Fatalf("gzip magic: got %x", batch.CompressedJsonl[:2])
	}
	if got, want := mustGunzipString(t, batch.CompressedJsonl), "{\"rule_id\":\"a\"}\n{\"rule_id\":\"b\"}\n"; got != want {
		t.Fatalf("jsonl: got %q, want %q", got, want)
	}
}

func TestBuildCollectorIngestLogBatch_RecordBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		records   [][]byte
		wantBody  string
		wantError string
	}{
		{
			name:      "no records",
			records:   nil,
			wantError: "no records",
		},
		{
			name:      "all empty records",
			records:   [][]byte{nil, {}, []byte("")},
			wantError: "no non-empty records",
		},
		{
			name:     "mixed empty records are skipped",
			records:  [][]byte{nil, []byte(`{"n":1}`), {}, []byte(`{"n":2}`)},
			wantBody: "{\"n\":1}\n{\"n\":2}\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batch, err := BuildCollectorIngestLogBatch(LogBatch{
				Identity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
				Scope:    managerv1.Scope_SCOPE_PROJECT,
				Type:     managerv1.LogType_LOG_TYPE_SUMMARY,
				Records:  tt.records,
				FlushAt:  time.Now(),
			})
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error: got %v, want substring %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("build batch: %v", err)
			}
			if got := mustGunzipString(t, batch.GetCompressedJsonl()); got != tt.wantBody {
				t.Fatalf("jsonl: got %q, want %q", got, tt.wantBody)
			}
		})
	}
}

func TestBuildCollectorIngestLogBatch_GitLabIdentity(t *testing.T) {
	identity := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	batch, err := BuildCollectorIngestLogBatch(LogBatch{
		Identity: identity,
		Scope:    managerv1.Scope_SCOPE_PROJECT,
		Type:     managerv1.LogType_LOG_TYPE_SUMMARY,
		Records:  [][]byte{[]byte(`{"ok":true}`)},
		FlushAt:  time.Now(),
	})
	if err != nil {
		t.Fatalf("build batch: %v", err)
	}
	got := batch.GetJobIdentity()
	if got.GetProviderHost() != identity.ProviderHost ||
		got.GetProjectPath() != identity.ProjectPath ||
		got.GetGitlabJobId() != identity.GitLabJobID {
		t.Fatalf("gitlab job_identity fields: got %+v", got)
	}
}

func mustGunzipString(t *testing.T, compressed []byte) string {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return string(body)
}
