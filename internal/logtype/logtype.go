// Package logtype names the three top-level job-log types shared by the
// agent (emitter) and the manager (router). Centralised so the agent's
// `log_type` JSON field and the manager's routing keys cannot drift.
package logtype

// LogType identifies a top-level job log stream.
type LogType string

const (
	Detection    LogType = "detection_log"
	RuntimeEvent LogType = "runtime_event_log"
	Summary      LogType = "summary_log"
)

// Schema versions per log type. Bump on breaking changes (rename / retype /
// remove a field, or change a field's semantics). Do NOT bump for additive
// changes like adding a new column.
const (
	DetectionSchemaVersion    = "v1"
	RuntimeEventSchemaVersion = "v1"
	SummarySchemaVersion      = "v1"
)

// Parse returns the matching LogType for value, or (zero, false) if value is
// not a known type.
func Parse(value string) (LogType, bool) {
	switch LogType(value) {
	case Detection, RuntimeEvent, Summary:
		return LogType(value), true
	default:
		return "", false
	}
}
