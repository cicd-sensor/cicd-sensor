package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/ctl/report"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

// renderAttestationJSON renders and parses the attestation predicate so tests
// can assert on the wire shape without re-implementing the projection.
func renderAttestationJSON(t *testing.T, log resultdoc.JobEventSummaryForReport) attestationWire {
	t.Helper()

	var buf bytes.Buffer
	if err := report.RenderAttestation(&buf, &log); err != nil {
		t.Fatalf("RenderAttestation: %v", err)
	}
	var got attestationWire
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal attestation: %v\n%s", err, buf.String())
	}
	return got
}

type ruleHitWire struct {
	RulesetID       string `json:"ruleset_id,omitempty"`
	RuleID          string `json:"rule_id,omitempty"`
	RulesetRevision string `json:"ruleset_revision,omitempty"`
	Action          string `json:"action,omitempty"`
	Count           uint32 `json:"count,omitempty"`
}

// jobWire mirrors log.v1 LogContext keys we care about in tests. We unmarshal
// loosely because protojson emits empty strings depending on field presence.
type jobWire struct {
	Provider          string `json:"provider,omitempty"`
	ProviderHost      string `json:"provider_host,omitempty"`
	ProjectPath       string `json:"project_path,omitempty"`
	CommitSHA         string `json:"commit_sha,omitempty"`
	ActorName         string `json:"actor_name,omitempty"`
	GitHubRunID       string `json:"github_run_id,omitempty"`
	GitHubWorkflow    string `json:"github_workflow,omitempty"`
	GitHubWorkflowRef string `json:"github_workflow_ref,omitempty"`
}

type metadataWire struct {
	BuildStartedOn  string `json:"buildStartedOn,omitempty"`
	BuildFinishedOn string `json:"buildFinishedOn,omitempty"`
}

type attestationWire struct {
	MonitorLog struct {
		Network    []string      `json:"network"`
		Detections []ruleHitWire `json:"https://cicd-sensor.github.io/runtime_trace/detections/v1alpha1"`
		Domains    []string      `json:"https://cicd-sensor.github.io/runtime_trace/domains/v1alpha1"`
		Result     string        `json:"https://cicd-sensor.github.io/runtime_trace/result/v1alpha1"`
		Job        jobWire       `json:"https://cicd-sensor.github.io/runtime_trace/job/v1alpha1"`
	} `json:"monitorLog"`
	Metadata metadataWire `json:"metadata"`
}

// minimalLogForIdentity builds a minimal JobEventSummaryForReport so tests can
// extend it with the bits they care about.
func minimalLogForIdentity() resultdoc.JobEventSummaryForReport {
	return resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity(
			"github.com", "acme/example", "1", "build", "1", "runner",
		),
	}
}

func TestRenderAttestation_HappyPath(t *testing.T) {
	t.Parallel()

	log := sampleResultLog()
	var buf bytes.Buffer
	if err := report.RenderAttestation(&buf, &log); err != nil {
		t.Fatalf("RenderAttestation: %v", err)
	}

	got := buf.String()
	if !json.Valid([]byte(strings.TrimSpace(got))) {
		t.Fatalf("output is not valid JSON: %s", got)
	}

	for _, key := range []string{
		`"network"`,
		`"https://cicd-sensor.github.io/runtime_trace/detections/v1alpha1"`,
		`"https://cicd-sensor.github.io/runtime_trace/domains/v1alpha1"`,
		`"https://cicd-sensor.github.io/runtime_trace/result/v1alpha1"`,
		`"https://cicd-sensor.github.io/runtime_trace/job/v1alpha1"`,
	} {
		if !strings.Contains(got, key) {
			t.Fatalf("missing fragment %q in output:\n%s", key, got)
		}
	}
	wire := renderAttestationJSON(t, log)
	if wire.MonitorLog.Result != "detected" {
		t.Errorf("result: got %q, want %q", wire.MonitorLog.Result, "detected")
	}
	if got, want := wire.Metadata.BuildStartedOn, "2026-04-30T12:00:00Z"; got != want {
		t.Errorf("metadata.buildStartedOn: got %q, want %q", got, want)
	}
	if got, want := wire.Metadata.BuildFinishedOn, "2026-04-30T12:05:00Z"; got != want {
		t.Errorf("metadata.buildFinishedOn: got %q, want %q", got, want)
	}
	if len(wire.MonitorLog.Detections) != 1 {
		t.Fatalf("detections: got %d, want 1", len(wire.MonitorLog.Detections))
	}
	d := wire.MonitorLog.Detections[0]
	if d.RulesetID != "set" || d.RuleID != "curl-egress" || d.Action != "detect" || d.Count != 1 {
		t.Errorf("detection entry: got %#v", d)
	}
	for _, mustNotContain := range []string{
		`"fileAccess"`,
		`"https://cicd-sensor.github.io/terminations"`,
		`"https://cicd-sensor.github.io/hits"`,
		`"https://cicd-sensor.github.io/actions"`,
		`"https://cicd-sensor.github.io/job-identity"`,
		`"https://cicd-sensor.github.io/metadata"`,
		`"hits_count"`,
	} {
		if strings.Contains(got, mustNotContain) {
			t.Fatalf("unexpected fragment %q in output:\n%s", mustNotContain, got)
		}
	}
}

func TestAttestationPredicate_KeepsDetectAndTerminateActions(t *testing.T) {
	t.Parallel()

	log := resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity(
			"github.com", "acme/example", "1", "build", "1", "runner",
		),
		Hits: []resultdoc.HitRecord{
			{RulesetID: "s", RuleID: "warn-rule", Action: "detect", HitCount: 2},
			{RulesetID: "s", RuleID: "kill-rule", Action: "terminate", HitCount: 1},
			{RulesetID: "s", RuleID: "collect-rule", Action: "collect", HitCount: 5},
		},
	}
	var buf bytes.Buffer
	if err := report.RenderAttestation(&buf, &log); err != nil {
		t.Fatalf("RenderAttestation: %v", err)
	}

	var got attestationWire
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.MonitorLog.Detections) != 2 {
		t.Fatalf("detections: got %#v, want 2 entries (warn + kill)", got.MonitorLog.Detections)
	}
	want := map[string]struct {
		action string
		count  uint32
	}{
		"warn-rule": {"detect", 2},
		"kill-rule": {"terminate", 1},
	}
	for _, d := range got.MonitorLog.Detections {
		w, ok := want[d.RuleID]
		if !ok {
			t.Errorf("unexpected rule %q in detections", d.RuleID)
			continue
		}
		if d.Action != w.action || d.Count != w.count {
			t.Errorf("rule %q: got action=%q count=%d, want action=%q count=%d", d.RuleID, d.Action, d.Count, w.action, w.count)
		}
	}
	if strings.Contains(buf.String(), "collect-rule") {
		t.Fatalf("collect hits must not appear in attestation; got:\n%s", buf.String())
	}
}

func TestAttestationPredicate_DropsUnknownActions(t *testing.T) {
	t.Parallel()

	log := minimalLogForIdentity()
	log.Hits = []resultdoc.HitRecord{
		{RulesetID: "s", RuleID: "empty", Action: ""},
		{RulesetID: "s", RuleID: "unknown", Action: "delete"},
		{RulesetID: "s", RuleID: "ok", Action: "detect"},
	}

	got := renderAttestationJSON(t, log)
	if len(got.MonitorLog.Detections) != 1 || got.MonitorLog.Detections[0].RuleID != "ok" {
		t.Fatalf("detections: got %#v, want only the detect hit", got.MonitorLog.Detections)
	}
}

func TestAttestationPredicate_PreservesRuleHitsOrder(t *testing.T) {
	t.Parallel()

	log := minimalLogForIdentity()
	log.Hits = []resultdoc.HitRecord{
		{RulesetID: "s", RuleID: "a", Action: "detect"},
		{RulesetID: "s", RuleID: "b", Action: "terminate"},
		{RulesetID: "s", RuleID: "c", Action: "detect"},
	}

	got := renderAttestationJSON(t, log)
	if len(got.MonitorLog.Detections) != 3 {
		t.Fatalf("detections: got %d, want 3", len(got.MonitorLog.Detections))
	}
	wantOrder := []string{"a", "b", "c"}
	for i, w := range wantOrder {
		if got.MonitorLog.Detections[i].RuleID != w {
			t.Fatalf("rule order: got %q at %d, want %q", got.MonitorLog.Detections[i].RuleID, i, w)
		}
	}
}

func TestAttestationPredicate_KeepsRuleIdentityOmitsEventAndPerHitDetail(t *testing.T) {
	t.Parallel()

	log := minimalLogForIdentity()
	// HitCount = 7 (5 retained + 2 dropped). Per-event detail attached;
	// none of it should leak into the predicate.
	mkEvent := func() resultdoc.AlertEvent {
		return resultdoc.AlertEvent{
			Timestamp: time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
			EventType: "process_exec",
			Process: &resultdoc.ProcessSummary{
				PID: 99, ExecPath: "/usr/bin/curl",
			},
			Payload: map[string]any{"remote_ip": "203.0.113.10"},
		}
	}
	log.Hits = []resultdoc.HitRecord{{
		RulesetID:       "set",
		RuleID:          "rule-x",
		RulesetRevision: "rev123",
		RuleName:        "should not appear",
		RuleType:        "correlation",
		RuleCondition:   "should not appear",
		Action:          "detect",
		HitCount:        7,
		MaxAlerts:       5,
		AlertEvents:     []resultdoc.AlertEvent{mkEvent(), mkEvent(), mkEvent(), mkEvent(), mkEvent()},
	}}

	var buf bytes.Buffer
	if err := report.RenderAttestation(&buf, &log); err != nil {
		t.Fatalf("RenderAttestation: %v", err)
	}
	raw := buf.String()

	wire := renderAttestationJSON(t, log)
	if len(wire.MonitorLog.Detections) != 1 {
		t.Fatalf("detections: got %d, want 1", len(wire.MonitorLog.Detections))
	}
	d := wire.MonitorLog.Detections[0]
	if d.RulesetID != "set" || d.RuleID != "rule-x" || d.RulesetRevision != "rev123" ||
		d.Action != "detect" || d.Count != 7 {
		t.Errorf("detection entry: got %#v", d)
	}

	for _, mustNot := range []string{
		`"timestamp"`,
		`"rule_name"`,
		`"rule_type"`,
		`"rule_condition"`,
		`"event_type"`,
		`"process"`,
		`"payload"`,
		`"alert_truncation"`,
		`"alert_cap"`,
		`"alert_dropped"`,
	} {
		if strings.Contains(raw, mustNot) {
			t.Errorf("predicate must not embed %s; got:\n%s", mustNot, raw)
		}
	}
}

func TestAttestationPredicate_NetworkDedupAndSort(t *testing.T) {
	t.Parallel()

	log := minimalLogForIdentity()
	log.NetworkConnections = []resultdoc.NetworkConnection{
		{RemoteIP: "10.0.0.2"},
		{RemoteIP: "10.0.0.1"},
		{RemoteIP: ""},                          // empty IP must be skipped
		{RemoteIP: "10.0.0.1"},                  // duplicate must be deduped
		{RemoteIP: "2606:4700::6810:122"},       // IPv6 should pass through
		{RemoteIP: "10.0.0.1", Protocol: "udp"}, // duplicate with different port/proto still dedups
	}

	got := renderAttestationJSON(t, log)
	want := []string{"10.0.0.1", "10.0.0.2", "2606:4700::6810:122"}
	if !equalStringSlices(got.MonitorLog.Network, want) {
		t.Fatalf("network: got %v, want %v", got.MonitorLog.Network, want)
	}
}

func TestAttestationPredicate_DomainsDedupAndSort(t *testing.T) {
	t.Parallel()

	log := minimalLogForIdentity()
	log.DomainObservations = []resultdoc.DomainObservation{
		{Domain: "b.example.com"},
		{Domain: "a.example.com"},
		{Domain: ""}, // empty must be skipped
		{Domain: "a.example.com"},
		{Domain: "xn--n3h.example"}, // punycode is preserved as-is
	}

	got := renderAttestationJSON(t, log)
	want := []string{"a.example.com", "b.example.com", "xn--n3h.example"}
	if !equalStringSlices(got.MonitorLog.Domains, want) {
		t.Fatalf("domains: got %v, want %v", got.MonitorLog.Domains, want)
	}
}

func TestAttestationPredicate_GitLabJobIdentityRoundTrip(t *testing.T) {
	t.Parallel()

	log := resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "42"),
	}
	got := renderAttestationJSON(t, log)
	if got.MonitorLog.Job.ProjectPath != "group/project" {
		t.Errorf("project_path: got %q, want %q",
			got.MonitorLog.Job.ProjectPath, "group/project")
	}
	if got.MonitorLog.Job.ProviderHost != "gitlab.com" {
		t.Errorf("provider_host: got %q, want %q",
			got.MonitorLog.Job.ProviderHost, "gitlab.com")
	}
}

func TestAttestationPredicate_PreservesMetadata(t *testing.T) {
	t.Parallel()

	log := minimalLogForIdentity()
	log.Metadata = jobcontext.JobMetadata{
		CommitSHA:         "def456",
		RefName:           "main",
		Trigger:           "push",
		ActorName:         "alice",
		GitHubWorkflowRef: "refs/heads/main",
		GitHubWorkflowSHA: "abc123",
		GitHubWorkflow:    "release",
	}

	got := renderAttestationJSON(t, log)
	if got.MonitorLog.Job.GitHubWorkflow != "release" {
		t.Errorf("github_workflow: got %q, want %q", got.MonitorLog.Job.GitHubWorkflow, "release")
	}
	if got.MonitorLog.Job.ActorName != "alice" {
		t.Errorf("actor_name: got %q, want %q", got.MonitorLog.Job.ActorName, "alice")
	}
	if got.MonitorLog.Job.CommitSHA != "def456" {
		t.Errorf("commit_sha: got %q, want %q", got.MonitorLog.Job.CommitSHA, "def456")
	}
}

func TestAttestationPredicate_PreservesResultSummary(t *testing.T) {
	t.Parallel()

	log := minimalLogForIdentity()
	log.ResultSummary = resultdoc.ResultSummary{
		Result: resultdoc.ResultTerminated,
	}

	got := renderAttestationJSON(t, log)
	if got.MonitorLog.Result != resultdoc.ResultTerminated {
		t.Errorf("result: got %q, want %q", got.MonitorLog.Result, resultdoc.ResultTerminated)
	}
	var buf bytes.Buffer
	if err := report.RenderAttestation(&buf, &log); err != nil {
		t.Fatalf("RenderAttestation: %v", err)
	}
	if strings.Contains(buf.String(), "hits_count") {
		t.Errorf("hits_count must not appear in predicate:\n%s", buf.String())
	}
}

// failingWriter fails on the first Write call so tests can verify error
// propagation from RenderAttestation.
type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRenderAttestation_PropagatesWriterError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("disk full")
	log := minimalLogForIdentity()
	err := report.RenderAttestation(failingWriter{err: wantErr}, &log)
	if !errors.Is(err, wantErr) {
		t.Fatalf("RenderAttestation: got %v, want wrapping %v", err, wantErr)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
