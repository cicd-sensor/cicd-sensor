// Package resultdoc defines the project result document consumed by reports.
package resultdoc

import (
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

const (
	AlertTruncationMaxAlertsReached = "rule reached its max_alerts cap; further hits in this Job are counted but detailed alert records are omitted"
)

const (
	ResultNoAlert    = "no_alert"
	ResultDetected   = "detected"
	ResultTerminated = "terminated"
)

// JobEventSummaryForReport is the large project result document returned by
// `cicd-sensor project result` and consumed by cicd-sensorctl reports.
type JobEventSummaryForReport struct {
	JobIdentity        jobcontext.JobIdentity `json:"job_identity"`
	Metadata           jobcontext.JobMetadata `json:"metadata"`
	RunnerType         string                 `json:"runner_type,omitempty"`
	StartedAt          time.Time              `json:"started_at"`
	GeneratedAt        time.Time              `json:"generated_at"`
	FinalizeReason     string                 `json:"finalize_reason"`
	RulesSummary       RulesSummary           `json:"rules_summary"`
	ResultSummary      ResultSummary          `json:"result_summary"`
	NetworkConnections []NetworkConnection    `json:"network_connections"`
	DomainObservations []DomainObservation    `json:"domain_observations"`
	Hits               []HitRecord            `json:"hits"`
	ConfigRevision     string                 `json:"config_revision,omitempty"`
}

type RulesSummary struct {
	RuleCount     int `json:"rule_count"`
	WarningsCount int `json:"warnings_count"`
}

type ResultSummary struct {
	Result    string `json:"result"`
	HitsCount int    `json:"hits_count"`
}

type AncestorProcess struct {
	ExecPath string   `json:"exec_path,omitempty"`
	Argv     []string `json:"argv,omitempty"`
}

// ProcessSummary is report-document schema, not agent runtime state.
// Keep it separate so runtime-only fields do not leak into reports.
type ProcessSummary struct {
	PID           int32             `json:"pid,omitempty"`
	StartBoottime uint64            `json:"start_boottime,omitempty"`
	ExecPath      string            `json:"exec_path,omitempty"`
	Argv          []string          `json:"argv,omitempty"`
	Ancestors     []AncestorProcess `json:"ancestors,omitempty"`
}

type ObservationAncestorProcess struct {
	ExecPath string `json:"exec_path,omitempty"`
}

type ObservationProcess struct {
	PID           int32                        `json:"pid,omitempty"`
	StartBoottime uint64                       `json:"start_boottime,omitempty"`
	ExecPath      string                       `json:"exec_path,omitempty"`
	Ancestors     []ObservationAncestorProcess `json:"ancestors,omitempty"`
}

type DomainObservation struct {
	Domain               string               `json:"domain"`
	Processes            []ObservationProcess `json:"processes,omitempty"`
	ProcessOverflowCount int64                `json:"process_overflow_count,omitempty"`
}

type NetworkConnection struct {
	RemoteIP             string               `json:"remote_ip"`
	RemotePort           int64                `json:"remote_port,omitempty"`
	Protocol             string               `json:"protocol,omitempty"`
	Processes            []ObservationProcess `json:"processes,omitempty"`
	ProcessOverflowCount int64                `json:"process_overflow_count,omitempty"`
}

type HitRecord struct {
	Timestamp       time.Time       `json:"timestamp"`
	RulesetID       string          `json:"ruleset_id"`
	RuleID          string          `json:"rule_id"`
	RuleName        string          `json:"rule_name,omitempty"`
	RuleType        string          `json:"rule_type,omitempty"`
	RuleCondition   string          `json:"rule_condition,omitempty"`
	Action          string          `json:"action"`
	EventType       jobevent.Type   `json:"event_type,omitempty"`
	Process         *ProcessSummary `json:"process,omitempty"`
	Payload         map[string]any  `json:"payload,omitempty"`
	AlertTruncation string          `json:"alert_truncation,omitempty"`
	AlertCap        int             `json:"alert_cap,omitempty"`
	AlertDropped    int64           `json:"alert_dropped,omitempty"`
}
