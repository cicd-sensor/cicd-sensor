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

type attestationWire struct {
	MonitorLog struct {
		Network      []string                `json:"network"`
		Detections   []resultdoc.HitRecord   `json:"https://cicd-sensor.github.io/detections"`
		Terminations []resultdoc.HitRecord   `json:"https://cicd-sensor.github.io/terminations"`
		Domains      []string                `json:"https://cicd-sensor.github.io/domains"`
		Summary      resultdoc.ResultSummary `json:"https://cicd-sensor.github.io/summary"`
		JobIdentity  jobcontext.JobIdentity  `json:"https://cicd-sensor.github.io/job-identity"`
		Metadata     jobcontext.JobMetadata  `json:"https://cicd-sensor.github.io/metadata"`
		RunnerType   string                  `json:"https://cicd-sensor.github.io/runner-type"`
	} `json:"monitorLog"`
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

	for _, want := range []string{
		`"network"`,
		`"https://cicd-sensor.github.io/detections"`,
		`"https://cicd-sensor.github.io/terminations"`,
		`"https://cicd-sensor.github.io/domains"`,
		`"https://cicd-sensor.github.io/summary"`,
		`"https://cicd-sensor.github.io/job-identity"`,
		`"https://cicd-sensor.github.io/metadata"`,
		`"https://cicd-sensor.github.io/runner-type"`,
		`"result": "detected"`,
		`"machine"`,
		`"hits_count": 1`,
		`"ruleset_id": "set"`,
		`"rule_id": "curl-egress"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing fragment %q in output:\n%s", want, got)
		}
	}
	for _, mustNotContain := range []string{
		`"fileAccess"`,
		`"https://cicd-sensor.github.io/hits"`,
		`"https://cicd-sensor.github.io/actions"`,
	} {
		if strings.Contains(got, mustNotContain) {
			t.Fatalf("unexpected fragment %q in output:\n%s", mustNotContain, got)
		}
	}
}

func TestRenderAttestation_PreservesEmptyArrays(t *testing.T) {
	t.Parallel()

	log := resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "9"),
		ResultSummary: resultdoc.ResultSummary{
			Result: resultdoc.ResultNoAlert,
		},
	}
	var buf bytes.Buffer
	if err := report.RenderAttestation(&buf, &log); err != nil {
		t.Fatalf("RenderAttestation: %v", err)
	}

	got := buf.String()
	for _, want := range []string{
		`"network": []`,
		`"https://cicd-sensor.github.io/detections": []`,
		`"https://cicd-sensor.github.io/terminations": []`,
		`"https://cicd-sensor.github.io/domains": []`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing empty-array fragment %q in output:\n%s", want, got)
		}
	}
	if strings.Contains(got, ":null") || strings.Contains(got, ": null") {
		t.Fatalf("output should not contain null arrays:\n%s", got)
	}
}

func TestAttestationPredicate_SplitsHitsByAction(t *testing.T) {
	t.Parallel()

	log := resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity(
			"github.com", "acme/example", "1", "build", "1", "runner",
		),
		Hits: []resultdoc.HitRecord{
			{RulesetID: "s", RuleID: "warn-rule", Action: "detect"},
			{RulesetID: "s", RuleID: "kill-rule", Action: "terminate"},
			{RulesetID: "s", RuleID: "collect-rule", Action: "collect"},
		},
	}
	var buf bytes.Buffer
	if err := report.RenderAttestation(&buf, &log); err != nil {
		t.Fatalf("RenderAttestation: %v", err)
	}

	var got struct {
		MonitorLog struct {
			Detections   []resultdoc.HitRecord `json:"https://cicd-sensor.github.io/detections"`
			Terminations []resultdoc.HitRecord `json:"https://cicd-sensor.github.io/terminations"`
		} `json:"monitorLog"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.MonitorLog.Detections) != 1 || got.MonitorLog.Detections[0].RuleID != "warn-rule" {
		t.Fatalf("detections: got %#v, want one warn-rule entry", got.MonitorLog.Detections)
	}
	if len(got.MonitorLog.Terminations) != 1 || got.MonitorLog.Terminations[0].RuleID != "kill-rule" {
		t.Fatalf("terminations: got %#v, want one kill-rule entry", got.MonitorLog.Terminations)
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
	if len(got.MonitorLog.Terminations) != 0 {
		t.Fatalf("terminations: got %#v, want empty", got.MonitorLog.Terminations)
	}
}

func TestAttestationPredicate_PreservesHitOrder(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	log := minimalLogForIdentity()
	log.Hits = []resultdoc.HitRecord{
		{RulesetID: "s", RuleID: "d1", Action: "detect", Timestamp: t0},
		{RulesetID: "s", RuleID: "t1", Action: "terminate", Timestamp: t0.Add(1 * time.Second)},
		{RulesetID: "s", RuleID: "d2", Action: "detect", Timestamp: t0.Add(2 * time.Second)},
		{RulesetID: "s", RuleID: "t2", Action: "terminate", Timestamp: t0.Add(3 * time.Second)},
	}

	got := renderAttestationJSON(t, log)
	if len(got.MonitorLog.Detections) != 2 ||
		got.MonitorLog.Detections[0].RuleID != "d1" ||
		got.MonitorLog.Detections[1].RuleID != "d2" {
		t.Fatalf("detection order: got %#v, want [d1, d2]", got.MonitorLog.Detections)
	}
	if len(got.MonitorLog.Terminations) != 2 ||
		got.MonitorLog.Terminations[0].RuleID != "t1" ||
		got.MonitorLog.Terminations[1].RuleID != "t2" {
		t.Fatalf("termination order: got %#v, want [t1, t2]", got.MonitorLog.Terminations)
	}
}

func TestAttestationPredicate_PreservesHitRecordFields(t *testing.T) {
	t.Parallel()

	hit := resultdoc.HitRecord{
		Timestamp:     time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
		RulesetID:     "set",
		RuleID:        "rule-x",
		RuleName:      "rule x",
		RuleType:      "correlation",
		RuleCondition: "first && second",
		Action:        "detect",
		EventType:     "process_exec",
		Process: &resultdoc.ProcessSummary{
			PID:      99,
			ExecPath: "/usr/bin/curl",
			Argv:     []string{"curl", "https://example.com"},
			Ancestors: []resultdoc.AncestorProcess{
				{ExecPath: "/bin/bash", Argv: []string{"bash", "-c", "curl https://example.com"}},
			},
		},
		Payload:         map[string]any{"remote_ip": "203.0.113.10"},
		AlertTruncation: resultdoc.AlertTruncationMaxAlertsReached,
		AlertCap:        3,
		AlertDropped:    7,
	}
	log := minimalLogForIdentity()
	log.Hits = []resultdoc.HitRecord{hit}

	got := renderAttestationJSON(t, log)
	if len(got.MonitorLog.Detections) != 1 {
		t.Fatalf("detections: got %d, want 1", len(got.MonitorLog.Detections))
	}
	d := got.MonitorLog.Detections[0]
	if d.RuleID != hit.RuleID || d.RuleName != hit.RuleName || d.RuleType != hit.RuleType {
		t.Errorf("rule metadata not preserved: %#v", d)
	}
	if d.RuleCondition != hit.RuleCondition {
		t.Errorf("rule_condition not preserved: %q", d.RuleCondition)
	}
	if d.EventType != hit.EventType {
		t.Errorf("event_type not preserved: %q", d.EventType)
	}
	if d.Process == nil || d.Process.ExecPath != hit.Process.ExecPath {
		t.Fatalf("process not preserved: %#v", d.Process)
	}
	if len(d.Process.Argv) != 2 || d.Process.Argv[0] != "curl" {
		t.Errorf("process argv not preserved: %#v", d.Process.Argv)
	}
	if len(d.Process.Ancestors) != 1 || d.Process.Ancestors[0].ExecPath != "/bin/bash" {
		t.Errorf("ancestor not preserved: %#v", d.Process.Ancestors)
	}
	if got, want := d.Payload["remote_ip"], any("203.0.113.10"); got != want {
		t.Errorf("payload not preserved: got %v, want %v", got, want)
	}
	if d.AlertTruncation == "" || d.AlertCap != 3 || d.AlertDropped != 7 {
		t.Errorf("truncation markers not preserved: %#v", d)
	}
	if !d.Timestamp.Equal(hit.Timestamp) {
		t.Errorf("timestamp not preserved: got %v, want %v", d.Timestamp, hit.Timestamp)
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

func TestAttestationPredicate_OmitsEmptyRunnerType(t *testing.T) {
	t.Parallel()

	log := minimalLogForIdentity()
	log.RunnerType = ""

	var buf bytes.Buffer
	if err := report.RenderAttestation(&buf, &log); err != nil {
		t.Fatalf("RenderAttestation: %v", err)
	}
	if strings.Contains(buf.String(), `"https://cicd-sensor.github.io/runner-type"`) {
		t.Fatalf("runner-type key should be omitted when empty:\n%s", buf.String())
	}
}

func TestAttestationPredicate_KeepsRunnerTypeWhenSet(t *testing.T) {
	t.Parallel()

	log := minimalLogForIdentity()
	log.RunnerType = "kubernetes"

	got := renderAttestationJSON(t, log)
	if got.MonitorLog.RunnerType != "kubernetes" {
		t.Fatalf("runner-type: got %q, want %q", got.MonitorLog.RunnerType, "kubernetes")
	}
}

func TestAttestationPredicate_GitLabJobIdentityRoundTrip(t *testing.T) {
	t.Parallel()

	log := resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "42"),
	}
	got := renderAttestationJSON(t, log)
	if got.MonitorLog.JobIdentity.ProjectPath != "group/project" {
		t.Errorf("project_path: got %q, want %q",
			got.MonitorLog.JobIdentity.ProjectPath, "group/project")
	}
	if got.MonitorLog.JobIdentity.ProviderHost != "gitlab.com" {
		t.Errorf("provider_host: got %q, want %q",
			got.MonitorLog.JobIdentity.ProviderHost, "gitlab.com")
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
	if got.MonitorLog.Metadata.GitHubWorkflow != "release" {
		t.Errorf("github_workflow: got %q, want %q", got.MonitorLog.Metadata.GitHubWorkflow, "release")
	}
	if got.MonitorLog.Metadata.ActorName != "alice" {
		t.Errorf("actor_name: got %q, want %q", got.MonitorLog.Metadata.ActorName, "alice")
	}
	if got.MonitorLog.Metadata.CommitSHA != "def456" {
		t.Errorf("commit_sha: got %q, want %q", got.MonitorLog.Metadata.CommitSHA, "def456")
	}
}

func TestAttestationPredicate_PreservesResultSummary(t *testing.T) {
	t.Parallel()

	log := minimalLogForIdentity()
	log.ResultSummary = resultdoc.ResultSummary{
		Result:    resultdoc.ResultTerminated,
		HitsCount: 5,
	}

	got := renderAttestationJSON(t, log)
	if got.MonitorLog.Summary.Result != resultdoc.ResultTerminated {
		t.Errorf("result: got %q, want %q",
			got.MonitorLog.Summary.Result, resultdoc.ResultTerminated)
	}
	if got.MonitorLog.Summary.HitsCount != 5 {
		t.Errorf("hits_count: got %d, want 5", got.MonitorLog.Summary.HitsCount)
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
