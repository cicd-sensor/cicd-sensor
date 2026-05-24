package logtype

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  LogType
		ok    bool
	}{
		{name: "detection", input: "detection_log", want: Detection, ok: true},
		{name: "runtime event", input: "runtime_event_log", want: RuntimeEvent, ok: true},
		{name: "summary", input: "summary_log", want: Summary, ok: true},
		{name: "unknown", input: "detection", ok: false},
		{name: "empty", input: "", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Parse(tt.input)
			if ok != tt.ok {
				t.Fatalf("ok: got %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("type: got %q, want %q", got, tt.want)
			}
		})
	}
}
