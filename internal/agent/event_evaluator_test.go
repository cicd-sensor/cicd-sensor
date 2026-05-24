package agent_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/evaluation"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"google.golang.org/protobuf/encoding/protojson"
)

type recordingDetectionOutput struct {
	mu      sync.Mutex
	payload [][]byte
}

func (s *recordingDetectionOutput) Entries(t *testing.T) []*logv1.DetectionLogEntry {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*logv1.DetectionLogEntry, 0, len(s.payload))
	for _, payload := range s.payload {
		entry := &logv1.DetectionLogEntry{}
		if err := protojson.Unmarshal(payload, entry); err != nil {
			t.Fatalf("unmarshal detection entry: %v", err)
		}
		out = append(out, entry)
	}
	return out
}

func attachRecordingDetectionOutput(t *testing.T, scope *jobscope.JobScopeState, recorder *recordingDetectionOutput) {
	t.Helper()
	scope.ManagerJobLogsForTesting().AttachDetectionRecorderForTesting(
		jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		scope.Type,
		func(_ context.Context, batch managerclient.LogBatch) error {
			msg, err := managerclient.BuildCollectorIngestLogBatch(batch)
			if err != nil {
				return err
			}
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
			recorder.payload = append(recorder.payload, managerBatchRecords(t, msg)...)
			return nil
		},
	)
}

func attachRecordingRuntimeEventOutput(t *testing.T, scope *jobscope.JobScopeState, recorder *recordingRuntimeEventOutput) {
	t.Helper()
	scope.ManagerJobLogsForTesting().AttachRuntimeEventRecorderForTesting(
		jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		scope.Type,
		func(_ context.Context, batch managerclient.LogBatch) error {
			msg, err := managerclient.BuildCollectorIngestLogBatch(batch)
			if err != nil {
				return err
			}
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
			recorder.payload = append(recorder.payload, managerBatchRecords(t, msg)...)
			return nil
		},
	)
}

func closeRecordingOutputs(t *testing.T, scope *jobscope.JobScopeState) {
	t.Helper()
	if err := scope.ManagerJobLogsForTesting().FinalizeStreamingLogs(context.Background()); err != nil {
		t.Fatalf("finalize streaming outputs: %v", err)
	}
}

func managerBatchRecords(t *testing.T, batch *managerv1.IngestLogBatch) [][]byte {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(batch.CompressedJsonl))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip body: %v", err)
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	if len(data) == 0 {
		return nil
	}
	lines := bytes.Split(data, []byte("\n"))
	out := make([][]byte, 0, len(lines))
	for _, line := range lines {
		out = append(out, append([]byte(nil), line...))
	}
	return out
}

func TestEvaluateEvent_RoutesByActionAndScope(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{
			{
				RuleID:    "detect",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "example.com"`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "collect",
				EventType: jobevent.NetworkConnect,
				Condition: `protocol == "tcp"`,
				Action:    rule.RuleActionCollect,
			},
			{
				RuleID:    "terminate",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "example.com"`,
				Action:    rule.RuleActionTerminate,
			},
		},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)

	snapshot := hostScope.ObservationSnapshot()
	if len(detectHits(snapshot)) != 1 {
		t.Fatalf("hit_detect len: got %d, want 1", len(detectHits(snapshot)))
	}
	if len(collectHits(snapshot)) != 1 {
		t.Fatalf("hit_collect len: got %d, want 1", len(collectHits(snapshot)))
	}
	if len(preventHits(snapshot)) != 1 {
		t.Fatalf("hit_prevent len: got %d, want 1", len(preventHits(snapshot)))
	}
}

func TestEvaluateEvent_ExceptionsAndTypesSkipHits(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{
			{
				RuleID:     "with-exception",
				EventType:  jobevent.NetworkConnect,
				Condition:  `remote_ip == "example.com"`,
				Exceptions: `protocol == "tcp"`,
				Action:     rule.RuleActionDetect,
			},
			{
				RuleID:    "type-mismatch",
				EventType: jobevent.FileOpen,
				Condition: `path.contains(".env")`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "correlation-skip",
				Type:      "correlation",
				Condition: `rule.some.total_count >= 1`,
				Action:    rule.RuleActionTerminate,
			},
		},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)

	snapshot := hostScope.ObservationSnapshot()
	if len(detectHits(snapshot)) != 0 {
		t.Fatalf("hit_detect len: got %d, want 0", len(detectHits(snapshot)))
	}
	if len(preventHits(snapshot)) != 0 {
		t.Fatalf("hit_prevent len: got %d, want 0", len(preventHits(snapshot)))
	}
}

func TestEvaluateEvent_ModifierAddedExceptionSuppressesHit(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{
			{
				RuleID:    "with-added-exception",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "example.com"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}}
	hostScope.RuleModifiers = []rule.RuleModifier{{
		ModifierID:    "local/allow-curl",
		Targets:       []rule.RuleModifierTarget{{RulesetID: "host-set", RuleID: "with-added-exception"}},
		AddExceptions: `process_name == "curl"`,
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)

	snapshot := hostScope.ObservationSnapshot()
	if len(detectHits(snapshot)) != 0 {
		t.Fatalf("hit_detect len: got %d, want 0", len(detectHits(snapshot)))
	}
}

func TestEvaluateEvent_FileTypeHits(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{
			{
				RuleID:    "open-dotenv",
				EventType: jobevent.FileOpen,
				Condition: `path.endsWith(".env")`,
				Action:    rule.RuleActionDetect,
			},
		},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))

	evaluateTestRules(testCtx, eval, testFileOpenEvent("/workspace/.env"), hostScope, nil, testLogger)

	snapshot := hostScope.ObservationSnapshot()
	if len(detectHits(snapshot)) != 1 {
		t.Fatalf("hit_detect len: got %d, want 1", len(detectHits(snapshot)))
	}
}

func TestEvaluateEvent_EmitsDetectionLog(t *testing.T) {
	t.Parallel()

	stream := &recordingDetectionOutput{}
	hostScope := jobscope.NewHost()
	attachRecordingDetectionOutput(t, hostScope, stream)
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{
			{
				RuleID:    "detect",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "example.com"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	closeRecordingOutputs(t, hostScope)

	entries := stream.Entries(t)
	if len(entries) != 1 {
		t.Fatalf("detection entries: got %d, want 1", len(entries))
	}
	if entries[0].GetScope() != string(jobcontext.ScopeTypeHost) {
		t.Fatalf("scope: got %q, want %q", entries[0].GetScope(), string(jobcontext.ScopeTypeHost))
	}
	if detectionRuleRef(entries[0]) != "host-set/detect" {
		t.Fatalf("rule_id: got %q, want %q", detectionRuleRef(entries[0]), "host-set/detect")
	}
	if entries[0].GetEvent().GetId() == "" {
		t.Fatal("detection event id missing")
	}
}

func TestEvaluateEvent_ScopeFieldHostProject(t *testing.T) {
	t.Parallel()

	hostStream := &recordingDetectionOutput{}
	projectStream := &recordingDetectionOutput{}

	hostScope := jobscope.NewHost()
	attachRecordingDetectionOutput(t, hostScope, hostStream)
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "host-rule",
			EventType: jobevent.NetworkConnect,
			Condition: `protocol == "tcp"`,
			Action:    rule.RuleActionDetect,
		}},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	projectScope := jobscope.NewProject()
	attachRecordingDetectionOutput(t, projectScope, projectStream)
	projectScope.RuleSets = []rule.RuleSet{{
		RulesetID: "project-set",
		Rules: []rule.Rule{{
			RuleID:    "project-rule",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		}},
	}}
	projectScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(projectScope))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, projectScope, testLogger)
	closeRecordingOutputs(t, hostScope)
	closeRecordingOutputs(t, projectScope)

	hostEntries := hostStream.Entries(t)
	projectEntries := projectStream.Entries(t)
	if len(hostEntries) != 1 || hostEntries[0].GetScope() != string(jobcontext.ScopeTypeHost) {
		t.Fatalf("host entries: got %#v", hostEntries)
	}
	if len(projectEntries) != 1 || projectEntries[0].GetScope() != string(jobcontext.ScopeTypeProject) {
		t.Fatalf("project entries: got %#v", projectEntries)
	}
}

func TestEvaluateEvent_CollectHitEmitsDetectionLog(t *testing.T) {
	t.Parallel()

	stream := &recordingDetectionOutput{}
	hostScope := jobscope.NewHost()
	attachRecordingDetectionOutput(t, hostScope, stream)
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "collect",
			EventType: jobevent.NetworkConnect,
			Condition: `protocol == "tcp"`,
			Action:    rule.RuleActionCollect,
		}},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)
	closeRecordingOutputs(t, hostScope)

	entries := stream.Entries(t)
	if len(entries) != 1 {
		t.Fatalf("detection entries: got %d, want 1", len(entries))
	}
	if got, want := entries[0].GetAction(), string(rule.RuleActionCollect); got != want {
		t.Fatalf("action: got %q, want %q", got, want)
	}
}

func TestEvaluateEvent_EmitsRuntimeEventForAllEvents(t *testing.T) {
	t.Parallel()

	stream := &recordingRuntimeEventOutput{}
	hostScope := jobscope.NewHost()
	attachRecordingRuntimeEventOutput(t, hostScope, stream)
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "detect",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "not-matching.example"`,
			Action:    rule.RuleActionDetect,
		}},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	closeRecordingOutputs(t, hostScope)

	entries := stream.Entries(t)
	if len(entries) != 1 {
		t.Fatalf("runtime event entries: got %d, want 1", len(entries))
	}
	if entries[0].GetScope() != string(jobcontext.ScopeTypeHost) {
		t.Fatalf("scope: got %q, want %q", entries[0].GetScope(), string(jobcontext.ScopeTypeHost))
	}
	if entries[0].GetEvent().GetId() == "" {
		t.Fatal("event id missing")
	}
}

func TestEvaluateEvent_RuntimeEventDoesNotEmbedRuleHits(t *testing.T) {
	t.Parallel()

	stream := &recordingRuntimeEventOutput{}
	hostScope := jobscope.NewHost()
	attachRecordingRuntimeEventOutput(t, hostScope, stream)
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "detect",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		}},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)
	closeRecordingOutputs(t, hostScope)

	entries := stream.Entries(t)
	if len(entries) != 1 {
		t.Fatalf("runtime event entries: got %d, want 1", len(entries))
	}
	if entries[0].GetEvent().GetId() == "" {
		t.Fatal("event id missing")
	}
}

func TestEvaluateEvent_RuntimeEventScopeFieldHostProject(t *testing.T) {
	t.Parallel()

	hostStream := &recordingRuntimeEventOutput{}
	projectStream := &recordingRuntimeEventOutput{}

	hostScope := jobscope.NewHost()
	attachRecordingRuntimeEventOutput(t, hostScope, hostStream)
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "host-rule",
			EventType: jobevent.NetworkConnect,
			Condition: `protocol == "tcp"`,
			Action:    rule.RuleActionDetect,
		}},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	projectScope := jobscope.NewProject()
	attachRecordingRuntimeEventOutput(t, projectScope, projectStream)
	projectScope.RuleSets = []rule.RuleSet{{
		RulesetID: "project-set",
		Rules: []rule.Rule{{
			RuleID:    "project-rule",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		}},
	}}
	projectScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(projectScope))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, projectScope, testLogger)
	closeRecordingOutputs(t, hostScope)
	closeRecordingOutputs(t, projectScope)

	hostEntries := hostStream.Entries(t)
	projectEntries := projectStream.Entries(t)
	if len(hostEntries) != 1 || hostEntries[0].GetScope() != string(jobcontext.ScopeTypeHost) {
		t.Fatalf("host entries: got %#v", hostEntries)
	}
	if len(projectEntries) != 1 || projectEntries[0].GetScope() != string(jobcontext.ScopeTypeProject) {
		t.Fatalf("project entries: got %#v", projectEntries)
	}
}

func TestEvaluateEvent_RuntimeErrorWarnsAndContinues(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Lists: map[string][]string{
			"domains": {"example.com"},
		},
		Rules: []rule.Rule{
			{
				RuleID:    "runtime-error",
				EventType: jobevent.NetworkConnect,
				Condition: `list.domains.startsWith("x")`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "good",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "example.com"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	evaluateTestRules(testCtx, eval, event, hostScope, nil, logger)

	snapshot := hostScope.ObservationSnapshot()
	if len(detectHits(snapshot)) != 1 {
		t.Fatalf("hit_detect len: got %d, want 1", len(detectHits(snapshot)))
	}
	if summaryRuleRef(detectHits(snapshot)[0]) != "host-set/good" {
		t.Fatalf("rule_id: got %q, want %q", summaryRuleRef(detectHits(snapshot)[0]), "host-set/good")
	}
	if !strings.Contains(buf.String(), "rule_evaluation_failed") {
		t.Fatalf("expected warning log to contain rule_evaluation_failed, got %q", buf.String())
	}
}

func TestEvaluateEvent_ExceptionRuntimeErrorDoesNotSuppressHit(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Lists: map[string][]string{
			"domains": {"example.com"},
		},
		Rules: []rule.Rule{
			{
				RuleID:    "with-bad-exception",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "example.com"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}}
	hostScope.RuleModifiers = []rule.RuleModifier{{
		ModifierID:    "local/bad-exception",
		Targets:       []rule.RuleModifierTarget{{RulesetID: "host-set", RuleID: "with-bad-exception"}},
		AddExceptions: `list.domains.startsWith("x")`,
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	evaluateTestRules(testCtx, eval, event, hostScope, nil, logger)

	snapshot := hostScope.ObservationSnapshot()
	if len(detectHits(snapshot)) != 1 {
		t.Fatalf("hit_detect len: got %d, want 1", len(detectHits(snapshot)))
	}
	if summaryRuleRef(detectHits(snapshot)[0]) != "host-set/with-bad-exception" {
		t.Fatalf("rule_id: got %q, want %q", summaryRuleRef(detectHits(snapshot)[0]), "host-set/with-bad-exception")
	}
	logs := buf.String()
	if !strings.Contains(logs, "rule_exception_evaluation_failed") {
		t.Fatalf("expected warning log to contain rule_exception_evaluation_failed, got %q", logs)
	}
	if !strings.Contains(logs, "exception_source=\"list.domains.startsWith(\\\"x\\\")\"") {
		t.Fatalf("expected exception source in log, got %q", logs)
	}
	if !strings.Contains(logs, "modifier_identity=local/bad-exception") {
		t.Fatalf("expected modifier identity in log, got %q", logs)
	}
}

func TestEvaluateEvent_ExceptionShortCircuitsBeforeLaterRuntimeError(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Lists: map[string][]string{
			"domains": {"example.com"},
		},
		Rules: []rule.Rule{
			{
				RuleID:     "with-base-and-added-exception",
				EventType:  jobevent.NetworkConnect,
				Condition:  `remote_ip == "example.com"`,
				Exceptions: `process_name == "curl"`,
				Action:     rule.RuleActionDetect,
			},
		},
	}}
	hostScope.RuleModifiers = []rule.RuleModifier{{
		ModifierID:    "local/bad-second-exception",
		Targets:       []rule.RuleModifierTarget{{RulesetID: "host-set", RuleID: "with-base-and-added-exception"}},
		AddExceptions: `list.domains.startsWith("x")`,
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	evaluateTestRules(testCtx, eval, event, hostScope, nil, logger)

	snapshot := hostScope.ObservationSnapshot()
	if len(detectHits(snapshot)) != 0 {
		t.Fatalf("hit_detect len: got %d, want 0", len(detectHits(snapshot)))
	}
	if strings.Contains(buf.String(), "rule_exception_evaluation_failed") {
		t.Fatalf("expected no exception runtime error log after short-circuit, got %q", buf.String())
	}
}

func TestEvaluateEvent_MultipleMatchingRulesProduceMultipleHits(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{
			{
				RuleID:    "match-remote",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "example.com"`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "match-process",
				EventType: jobevent.NetworkConnect,
				Condition: `protocol == "tcp"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)

	snapshot := hostScope.ObservationSnapshot()
	if len(detectHits(snapshot)) != 2 {
		t.Fatalf("hit_detect len: got %d, want 2", len(detectHits(snapshot)))
	}

	got := map[string]bool{}
	for _, hit := range detectHits(snapshot) {
		got[summaryRuleRef(hit)] = true
	}
	if !got["host-set/match-remote"] || !got["host-set/match-process"] {
		t.Fatalf("rule ids: got %#v, want both matching rules", got)
	}
}

func TestJob_EventWorkerEvaluatesRulesAndFeedsOutputs(t *testing.T) {
	t.Parallel()

	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	metadata := jobcontext.JobMetadata{}
	job, eventCh := newTestJob(identity, metadata, testEventChannelSize)

	projectScope := jobscope.NewProject()
	projectScope.RuleSets = []rule.RuleSet{{
		RulesetID: "project-set",
		Rules: []rule.Rule{
			{
				RuleID:    "curl-egress",
				RuleName:  "Curl Egress",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "registry.npmjs.org" && protocol == "tcp"`,
				Action:    rule.RuleActionDetect,
				Tags: map[string]string{
					"severity": "medium",
				},
			},
		},
	}}
	projectScope.ResolveRules(jobcontext.JobIdentity{})
	if err := job.SetProjectScope(testCtx, projectScope); err != nil {
		t.Fatalf("SetProjectScope: %v", err)
	}

	sendTestEvent(t, eventCh, testDispatchEvent("/usr/bin/curl", "registry.npmjs.org", 443))

	waitForJob(t, "project scope hit detect populated", func() bool {
		return len(detectHits(projectScope.ObservationSnapshot())) == 1
	})

	logEntry := projectScope.BuildJobEventSummaryForReport(jobscope.ReportInputs{
		Identity:  job.Identity(),
		Metadata:  job.Metadata(),
		StartedAt: job.StartedAt(),
	}, "shutdown", time.Date(2026, 4, 16, 1, 2, 5, 0, time.UTC))
	if got := len(logEntry.Hits); got != 1 {
		t.Fatalf("hits: got %d, want 1", got)
	}
	if logEntry.ResultSummary.Result != resultdoc.ResultDetected {
		t.Fatalf("result_summary.result: got %q, want detected", logEntry.ResultSummary.Result)
	}
	if hitRecordRuleRef(logEntry.Hits[0]) != "project-set/curl-egress" {
		t.Fatalf("hits[0].rule_id: got %q, want %q", hitRecordRuleRef(logEntry.Hits[0]), "project-set/curl-egress")
	}

	finishTestJob(job, eventCh)
}

func TestJob_EventWorkerRoutesHostAndProjectHitsIndependently(t *testing.T) {
	t.Parallel()

	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	metadata := jobcontext.JobMetadata{}
	job, eventCh := newTestJob(identity, metadata, testEventChannelSize)

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{
			{
				RuleID:    "host-rule",
				EventType: jobevent.NetworkConnect,
				Condition: `protocol == "tcp"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})
	if err := job.SetHostScope(testCtx, hostScope); err != nil {
		t.Fatalf("SetHostScope: %v", err)
	}

	projectScope := jobscope.NewProject()
	projectScope.RuleSets = []rule.RuleSet{{
		RulesetID: "project-set",
		Rules: []rule.Rule{
			{
				RuleID:    "project-rule",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "example.com"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}}
	projectScope.ResolveRules(jobcontext.JobIdentity{})
	if err := job.SetProjectScope(testCtx, projectScope); err != nil {
		t.Fatalf("SetProjectScope: %v", err)
	}

	sendTestEvent(t, eventCh, testDispatchEvent("/usr/bin/curl", "example.com", 443))

	waitForJob(t, "host and project hit detect populated", func() bool {
		return len(detectHits(hostScope.ObservationSnapshot())) == 1 && len(detectHits(projectScope.ObservationSnapshot())) == 1
	})

	hostHits := detectHits(hostScope.ObservationSnapshot())
	projectHits := detectHits(projectScope.ObservationSnapshot())

	if summaryRuleRef(hostHits[0]) != "host-set/host-rule" {
		t.Fatalf("host rule_id: got %q, want %q", summaryRuleRef(hostHits[0]), "host-set/host-rule")
	}
	if summaryRuleRef(projectHits[0]) != "project-set/project-rule" {
		t.Fatalf("project rule_id: got %q, want %q", summaryRuleRef(projectHits[0]), "project-set/project-rule")
	}
	if summaryRuleRef(hostHits[0]) == summaryRuleRef(projectHits[0]) {
		t.Fatalf("scope routing should stay independent, got same rule id %q", summaryRuleRef(hostHits[0]))
	}

	finishTestJob(job, eventCh)
}

func testFileOpenEvent(path string) jobevent.EventRecord {
	return jobevent.EventRecord{
		EventType: jobevent.FileOpen,
		Timestamp: time.Date(2026, 4, 16, 1, 2, 3, 4, time.UTC),
		Payload: map[string]any{
			"path": path,
		},
		Process: jobevent.ProcessSummary{
			PID:      100,
			ExecPath: "/usr/bin/tester",
		},
		Tags: map[string]string{},
	}
}

// TestEvaluateEvent_FileMutationTypesEndToEnd locks the event payload →
// CEL eval pipeline for the three RFC 0002 §2 event types. Each case
// mirrors what event_file.go emits, so input projection regressions
// surface as missing or unwanted hits.
func TestEvaluateEvent_FileMutationTypesEndToEnd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		ruleEventType jobevent.Type
		ruleCondition string
		event         jobevent.EventRecord
		wantHitDetect int
	}{
		{
			name:          "file_remove_unlink_secret",
			ruleEventType: jobevent.FileRemove,
			ruleCondition: `!is_folder && path == "/etc/shadow"`,
			event: jobevent.EventRecord{
				EventType: jobevent.FileRemove,
				Payload: map[string]any{
					"path":      "/etc/shadow",
					"is_folder": false,
				},
				Process: jobevent.ProcessSummary{ExecPath: "/bin/rm"},
				Tags:    map[string]string{},
			},
			wantHitDetect: 1,
		},
		{
			name:          "file_remove_rmdir_skipped_by_is_folder_guard",
			ruleEventType: jobevent.FileRemove,
			ruleCondition: `!is_folder && path == "/var/log/journal"`,
			event: jobevent.EventRecord{
				EventType: jobevent.FileRemove,
				Payload: map[string]any{
					"path":      "/var/log/journal",
					"is_folder": true,
				},
				Process: jobevent.ProcessSummary{ExecPath: "/usr/bin/rmdir"},
				Tags:    map[string]string{},
			},
			wantHitDetect: 0,
		},
		{
			name:          "file_move_into_run_emits_both_paths",
			ruleEventType: jobevent.FileMove,
			ruleCondition: `from_path.startsWith("/tmp/") && to_path.startsWith("/run/")`,
			event: jobevent.EventRecord{
				EventType: jobevent.FileMove,
				Payload: map[string]any{
					"from_path": "/tmp/payload.bin",
					"to_path":   "/run/init",
				},
				Process: jobevent.ProcessSummary{ExecPath: "/usr/bin/mv"},
				Tags:    map[string]string{},
			},
			wantHitDetect: 1,
		},
		{
			name:          "file_link_symlink_into_local_bin",
			ruleEventType: jobevent.FileLink,
			ruleCondition: `is_symlink && created_path.startsWith("/usr/local/bin/") && existing_path.startsWith("/tmp/")`,
			event: jobevent.EventRecord{
				EventType: jobevent.FileLink,
				Payload: map[string]any{
					"created_path":  "/usr/local/bin/curl",
					"existing_path": "/tmp/wrap",
					"is_hardlink":   false,
					"is_symlink":    true,
				},
				Process: jobevent.ProcessSummary{ExecPath: "/usr/bin/ln"},
				Tags:    map[string]string{},
			},
			wantHitDetect: 1,
		},
		{
			name:          "file_link_hardlink_to_shadow",
			ruleEventType: jobevent.FileLink,
			ruleCondition: `is_hardlink && existing_path == "/etc/shadow" && process.exec_path.endsWith("/ln")`,
			event: jobevent.EventRecord{
				EventType: jobevent.FileLink,
				Payload: map[string]any{
					"created_path":  "/tmp/copy",
					"existing_path": "/etc/shadow",
					"is_hardlink":   true,
					"is_symlink":    false,
				},
				Process: jobevent.ProcessSummary{ExecPath: "/usr/bin/ln"},
				Tags:    map[string]string{},
			},
			wantHitDetect: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hostScope := jobscope.NewHost()
			hostScope.RuleSets = []rule.RuleSet{{
				RulesetID: "host-set",
				Rules: []rule.Rule{{
					RuleID:    "r1",
					EventType: tt.ruleEventType,
					Condition: tt.ruleCondition,
					Action:    rule.RuleActionDetect,
				}},
			}}
			hostScope.ResolveRules(jobcontext.JobIdentity{})

			eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
			evaluateTestRules(testCtx, eval, tt.event, hostScope, nil, testLogger)

			snapshot := hostScope.ObservationSnapshot()
			if got := len(detectHits(snapshot)); got != tt.wantHitDetect {
				t.Fatalf("hit_detect len: got %d, want %d", got, tt.wantHitDetect)
			}
		})
	}
}
