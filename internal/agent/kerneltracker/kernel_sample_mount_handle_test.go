package kerneltracker

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func TestHandleMountSample(t *testing.T) {
	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "mount")
	tests := []struct {
		name            string
		sourceTruncated bool
		targetTruncated bool
		wantTag         string
	}{
		{name: "complete_paths"},
		{name: "source_truncated", sourceTruncated: true, wantTag: "source_path"},
		{name: "target_truncated", targetTruncated: true, wantTag: "target_path"},
		{name: "both_truncated", sourceTruncated: true, targetTruncated: true, wantTag: "source_path,target_path"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := newJobTrackingState()
			state.bind(jobID, 100)
			sample := mountSample{
				Identity:        processIdentity{PID: 42, StartBoottime: 99},
				CgroupID:        100,
				TsNs:            1,
				SourcePath:      "/real/source",
				TargetPath:      "/mnt/target",
				SourceTruncated: test.sourceTruncated,
				TargetTruncated: test.targetTruncated,
			}

			effects := handleMountSample(state, sample)
			if len(effects) != 1 {
				t.Fatalf("effects length = %d, want 1", len(effects))
			}
			emit, ok := effects[0].(emitEventRecord)
			if !ok {
				t.Fatalf("effect = %T, want emitEventRecord", effects[0])
			}
			if emit.JobID != jobID {
				t.Fatalf("job ID = %#v, want %#v", emit.JobID, jobID)
			}
			record := emit.Record
			if record.EventType != jobevent.Mount {
				t.Fatalf("event type = %q, want %q", record.EventType, jobevent.Mount)
			}
			assertMountPayload(t, record.Payload, "source_path", "/real/source")
			assertMountPayload(t, record.Payload, "target_path", "/mnt/target")
			if got := record.Tags["truncated"]; got != test.wantTag {
				t.Fatalf("truncated tag = %q, want %q", got, test.wantTag)
			}
		})
	}
}

func TestHandleMountSampleIgnoresUntrackedCgroup(t *testing.T) {
	effects := handleMountSample(newJobTrackingState(), mountSample{CgroupID: 100})
	if len(effects) != 0 {
		t.Fatalf("effects length = %d, want 0", len(effects))
	}
}

func assertMountPayload(t *testing.T, payload map[string]any, key string, want any) {
	t.Helper()
	if got := payload[key]; got != want {
		t.Fatalf("payload[%q] = %#v, want %#v", key, got, want)
	}
}
