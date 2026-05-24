package logtype

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  LogType
		ok    bool
	}{
		{name: "detection", input: "detection", want: Detection, ok: true},
		{name: "runtime event", input: "runtime_event", want: RuntimeEvent, ok: true},
		{name: "summary", input: "summary", want: Summary, ok: true},
		{name: "unknown", input: "no_such_log", ok: false},
		{name: "empty", input: "", ok: false},
		{name: "wire form rejected", input: "cicd_sensor.summary", ok: false},
		{name: "legacy form rejected", input: "summary_log", ok: false},
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
