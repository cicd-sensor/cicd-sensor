// Package report renders derived artifacts from project result documents.
//
// HTML is self-contained so GitHub Actions can preview it as a plain artifact.
// The page reads the embedded JSON document's snake_case fields directly.
package report

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

//go:embed report.tmpl.html
var tmplSrc string

//go:embed logo.svg
var logoSVG string

// Non-default delimiters avoid collisions with JavaScript object literals.
var tmpl = template.Must(template.New("report").Delims("<<{", "}>>").Parse(tmplSrc))

// Render writes a single self-contained HTML report for log to w.
func Render(w io.Writer, log *resultdoc.JobEventSummaryForReport) error {
	js, err := json.Marshal(htmlReportFrom(log))
	if err != nil {
		return err
	}
	return tmpl.Execute(w, struct {
		Title string
		JSON  string
		Logo  template.HTML
	}{Title: reportTitle(log), JSON: string(js), Logo: template.HTML(logoSVG)})
}

// htmlHit is one event row consumed by the HTML report's JS. Pre-flattened
// in Go so the JS does no computation — it just renders.
type htmlHit struct {
	Timestamp       time.Time                 `json:"timestamp"`
	RulesetID       string                    `json:"ruleset_id"`
	RuleID          string                    `json:"rule_id"`
	RulesetRevision string                    `json:"ruleset_revision,omitempty"`
	RuleName        string                    `json:"rule_name,omitempty"`
	RuleDescription string                    `json:"rule_description,omitempty"`
	RuleType        string                    `json:"rule_type,omitempty"`
	RuleCondition   string                    `json:"rule_condition,omitempty"`
	RuleTags        map[string]string         `json:"rule_tags,omitempty"`
	Action          string                    `json:"action"`
	EventType       string                    `json:"event_type,omitempty"`
	Process         *resultdoc.ProcessSummary `json:"process,omitempty"`
	Payload         map[string]any            `json:"payload,omitempty"`
	AlertTruncation string                    `json:"alert_truncation,omitempty"`
	AlertCap        int                       `json:"alert_cap,omitempty"`
	AlertDropped    int64                     `json:"alert_dropped,omitempty"`
}

// htmlReport wraps the project result document but replaces per-rule Hits
// with the flat per-event list the HTML page expects, and forces domain
// observations through IDNA. The IDNA step is a *visual-spoofing*
// mitigation (IDN homograph) for human reviewers, not an XSS defense —
// html/template + textContent already covers XSS.
type htmlReport struct {
	*resultdoc.JobEventSummaryForReport
	Hits               []htmlHit                     `json:"hits"`
	DomainObservations []resultdoc.DomainObservation `json:"domain_observations"`
}

func htmlReportFrom(log *resultdoc.JobEventSummaryForReport) htmlReport {
	if log == nil {
		return htmlReport{}
	}
	flat := make([]htmlHit, 0, len(log.Hits))
	for _, h := range log.Hits {
		dropped := h.HitCount - int64(len(h.AlertEvents))
		for i, e := range h.AlertEvents {
			rec := htmlHit{
				Timestamp:       e.Timestamp,
				RulesetID:       h.RulesetID,
				RuleID:          h.RuleID,
				RulesetRevision: h.RulesetRevision,
				RuleName:        h.RuleName,
				RuleDescription: h.RuleDescription,
				RuleType:        h.RuleType,
				RuleCondition:   h.RuleCondition,
				RuleTags:        h.RuleTags,
				Action:          h.Action,
				EventType:       string(e.EventType),
				Process:         e.Process,
				Payload:         e.Payload,
			}
			if dropped > 0 && i == len(h.AlertEvents)-1 {
				rec.AlertTruncation = resultdoc.AlertTruncationMaxAlertsReached
				rec.AlertCap = h.MaxAlerts
				rec.AlertDropped = dropped
			}
			flat = append(flat, rec)
		}
	}
	domains := slices.Clone(log.DomainObservations)
	for i := range domains {
		domains[i].Domain = displayDomain(domains[i].Domain)
	}
	return htmlReport{JobEventSummaryForReport: log, Hits: flat, DomainObservations: domains}
}

func reportTitle(log *resultdoc.JobEventSummaryForReport) string {
	if log == nil {
		return "cicd-sensor report"
	}
	parts := make([]string, 0, 2)
	if !log.GeneratedAt.IsZero() {
		parts = append(parts, log.GeneratedAt.UTC().Format("2006-01-02"))
	}
	if projectPath := strings.TrimSpace(log.JobIdentity.ProjectPath); projectPath != "" {
		parts = append(parts, projectPath)
	}
	if len(parts) == 0 {
		return "cicd-sensor report"
	}
	return strings.Join(parts, " ") + " - cicd-sensor"
}
