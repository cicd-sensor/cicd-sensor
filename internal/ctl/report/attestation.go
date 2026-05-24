package report

// This file renders the in-toto runtime-trace predicate that cicd-sensor
// emits for each Job.
//
// We follow the in-toto runtime-trace predicate as defined in
// https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md.
//
// The spec gives a predicate body with two parts: `monitor` (info about the
// monitor itself, optional) and `monitorLog` (the actual evidence). Each
// monitorLog field is keyed by a URI identifying the schema of its value, so
// that generic in-toto consumers can ignore schemas they do not understand
// while preserving forward compatibility.
//
// cicd-sensor populates monitorLog with the policy outcomes and runtime
// context that matter for CI/CD:
//
//   - https://cicd-sensor.github.io/detections — HitRecord list for rules
//     whose action is `detect`.
//   - https://cicd-sensor.github.io/terminations — HitRecord list for rules
//     whose action is `terminate`. Splitting by action lets verifiers tell
//     "we observed and warned" from "we observed and stopped the process"
//     without re-deriving the distinction from the action string.
//   - network — IPs observed during the Job. Plain `network` key matches the
//     runtime-trace example, where common log types use unprefixed names.
//   - https://cicd-sensor.github.io/domains — domain names resolved during
//     the Job.
//   - https://cicd-sensor.github.io/summary, .../job-identity, .../metadata,
//     .../runner-type — Job context used by cicd-sensor-aware consumers.
//
// fileAccess is intentionally not emitted: cicd-sensor does not observe file
// events at the granularity attestation consumers expect, and emitting an
// always-empty field is misleading. `collect` hits are likewise excluded:
// the attestation records policy outcomes only (`detect`/`terminate`), while
// `collect` is non-enforcing collection surfaced through the job logs.

import (
	"encoding/json"
	"io"
	"slices"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

// runtimeTracePredicate is the in-toto runtime-trace predicate body that
// cicd-sensor produces. Only `monitorLog` is set today; a `monitor` block
// can be added later if downstream verifiers need it.
type runtimeTracePredicate struct {
	MonitorLog monitorLog `json:"monitorLog"`
}

// monitorLog mixes runtime-trace standard fields with cicd-sensor extension
// fields. Standard fields use plain keys; extensions use URI keys per the
// spec so that generic consumers can ignore unknown schemas.
type monitorLog struct {
	Network      []string                `json:"network"`
	Detections   []resultdoc.HitRecord   `json:"https://cicd-sensor.github.io/detections"`
	Terminations []resultdoc.HitRecord   `json:"https://cicd-sensor.github.io/terminations"`
	Domains      []string                `json:"https://cicd-sensor.github.io/domains"`
	Summary      resultdoc.ResultSummary `json:"https://cicd-sensor.github.io/summary"`
	JobIdentity  jobcontext.JobIdentity  `json:"https://cicd-sensor.github.io/job-identity"`
	Metadata     jobcontext.JobMetadata  `json:"https://cicd-sensor.github.io/metadata"`
	RunnerType   string                  `json:"https://cicd-sensor.github.io/runner-type,omitempty"`
}

// AttestationPredicate projects a result document into a runtime-trace
// predicate. Empty slices are kept as `[]` rather than null so that
// attestation consumers can rely on the field being present and of the
// expected type.
func AttestationPredicate(log resultdoc.JobEventSummaryForReport) any {
	detections, terminations := splitHitsByAction(log.Hits)
	return runtimeTracePredicate{
		MonitorLog: monitorLog{
			Network:      networkStrings(log.NetworkConnections),
			Detections:   detections,
			Terminations: terminations,
			Domains:      domainStrings(log.DomainObservations),
			Summary:      log.ResultSummary,
			JobIdentity:  log.JobIdentity,
			Metadata:     log.Metadata,
			RunnerType:   log.RunnerType,
		},
	}
}

// splitHitsByAction routes each hit to the detection or termination list
// based on its rule action. `collect` and any other action are dropped:
// the attestation records policy outcomes only, not collection-style hits.
func splitHitsByAction(hits []resultdoc.HitRecord) (detections, terminations []resultdoc.HitRecord) {
	detections = []resultdoc.HitRecord{}
	terminations = []resultdoc.HitRecord{}
	for _, h := range hits {
		switch h.Action {
		case string(rule.RuleActionDetect):
			detections = append(detections, h)
		case string(rule.RuleActionTerminate):
			terminations = append(terminations, h)
		}
	}
	return detections, terminations
}

func networkStrings(records []resultdoc.NetworkConnection) []string {
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.RemoteIP == "" {
			continue
		}
		seen[record.RemoteIP] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	slices.Sort(out)
	return out
}

func domainStrings(records []resultdoc.DomainObservation) []string {
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.Domain == "" {
			continue
		}
		seen[record.Domain] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for domain := range seen {
		out = append(out, domain)
	}
	slices.Sort(out)
	return out
}

// RenderAttestation writes a runtime-trace attestation predicate for log to w.
func RenderAttestation(w io.Writer, log *resultdoc.JobEventSummaryForReport) error {
	body, err := json.MarshalIndent(AttestationPredicate(*log), "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	_, err = w.Write(body)
	return err
}
