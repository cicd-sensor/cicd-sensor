package sink

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

func TestPubSubFlushPolicy(t *testing.T) {
	tests := []struct {
		name    string
		logKind logtype.LogType
		want    FlushPolicy
	}{
		{
			name:    "detection is immediate",
			logKind: logtype.Detection,
			want:    FlushPolicy{FlushThresholdBytes: 1, FlushIntervalSeconds: 1},
		},
		{
			name:    "runtime event batches briefly",
			logKind: logtype.RuntimeEvent,
			want:    FlushPolicy{FlushThresholdBytes: 256 * 1024, FlushIntervalSeconds: 5},
		},
		{
			name:    "result is immediate",
			logKind: logtype.Summary,
			want:    FlushPolicy{FlushThresholdBytes: 1, FlushIntervalSeconds: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (&pubsubSink{}).FlushPolicy(tt.logKind); got != tt.want {
				t.Fatalf("FlushPolicy(%q): got %+v, want %+v", tt.logKind, got, tt.want)
			}
		})
	}
}
