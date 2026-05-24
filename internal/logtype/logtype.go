// Package logtype names the three job-log types shared between the agent
// (emitter) and the manager (router) so their routing keys cannot drift.
//
// Two forms exist:
//   - Short ("summary", "detection", "runtime_event") — internal: routing
//     keys, sink prefixes, manager.yaml. Use LogType.String().
//   - Wire ("cicd_sensor.summary", ...) — JSON `log_type` only, the stable
//     routing key. Use LogType.Wire().
package logtype

type LogType string

const (
	Detection    LogType = "detection"
	RuntimeEvent LogType = "runtime_event"
	Summary      LogType = "summary"
)

// ServiceName is emitted in `service_name`. Kebab (human-readable component
// name), deliberately distinct from the wire log_type prefix.
const ServiceName = "cicd-sensor"

// Snake_case so the routing key matches the proto package (cicd_sensor.log.v1)
// and stays safe in glob/regex patterns where '-' is sometimes special.
const wireNamespace = "cicd_sensor."

// Wire returns the JSON `log_type` value (e.g. "cicd_sensor.summary").
func (t LogType) Wire() string { return wireNamespace + string(t) }

// Bump on breaking changes (rename/retype/remove a field, or change
// semantics). Additive changes do NOT bump.
const (
	DetectionSchemaVersion    = "v1"
	RuntimeEventSchemaVersion = "v1"
	SummarySchemaVersion      = "v1"
)

// Parse accepts the short form (as used in manager.yaml keys).
func Parse(value string) (LogType, bool) {
	switch LogType(value) {
	case Detection, RuntimeEvent, Summary:
		return LogType(value), true
	default:
		return "", false
	}
}
