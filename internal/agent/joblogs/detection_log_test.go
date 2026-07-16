package joblogs

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

func TestMarshalDetectionLogEntryAppliesProcessArgsRedactionPolicy(t *testing.T) {
	tests := []struct {
		name   string
		redact *bool
		assert func(*testing.T, *logv1beta1.EventRecord)
	}{
		{name: "nil policy defaults to sanitized output", assert: assertProtoEventProcessSanitized},
		{name: "explicit true sanitizes output", redact: boolPointer(true), assert: assertProtoEventProcessSanitized},
		{name: "explicit false preserves captured args", redact: boolPointer(false), assert: assertProtoEventProcessUnredacted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := eventWithSecretArgv()
			payload, err := MarshalDetectionLogEntry(DetectionLogInput{
				ScopeLogContext:   testScopeLogContext(),
				Hit:               testHitEntry(),
				Event:             event,
				RedactProcessArgs: tt.redact,
			})
			if err != nil {
				t.Fatalf("marshal detection log: %v", err)
			}

			var got logv1beta1.DetectionLogEntry
			if err := protojson.Unmarshal(payload, &got); err != nil {
				t.Fatalf("unmarshal detection log: %v", err)
			}
			tt.assert(t, got.GetEvent())
			if got, want := event.Process.Argv[1], "--token=supersecret"; got != want {
				t.Fatalf("input event argv mutated: got %q, want %q", got, want)
			}
		})
	}
}

func TestMarshalDetectionLogEntryNilHitReturnsNilPayload(t *testing.T) {
	t.Parallel()

	payload, err := MarshalDetectionLogEntry(DetectionLogInput{
		ScopeLogContext: testScopeLogContext(),
		Event:           eventWithSecretArgv(),
	})
	if err != nil {
		t.Fatalf("marshal detection log: %v", err)
	}
	if payload != nil {
		t.Fatalf("payload: got %q, want nil", payload)
	}
}

func TestMarshalDetectionLogEntryPopulatesRuleFields(t *testing.T) {
	t.Parallel()

	hit := testHitEntry()
	payload, err := MarshalDetectionLogEntry(DetectionLogInput{
		ScopeLogContext:     testScopeLogContext(),
		Hit:                 hit,
		Event:               eventWithSecretArgv(),
		RuleName:            "Curl token",
		RuleDescription:     "detects token leaks",
		RulesetRevision:     "rules-rev",
		RuleAlertTruncation: "max_alerts",
	})
	if err != nil {
		t.Fatalf("marshal detection log: %v", err)
	}

	var got logv1beta1.DetectionLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal detection log: %v", err)
	}
	if got.GetRulesetId() != hit.Identity.RulesetID || got.GetRuleId() != hit.Identity.RuleID {
		t.Fatalf("rule identity: got %s/%s", got.GetRulesetId(), got.GetRuleId())
	}
	if got.GetRulesetRevision() != "rules-rev" {
		t.Fatalf("ruleset revision: got %q", got.GetRulesetRevision())
	}
	if got.GetRuleName() != "Curl token" || got.GetRuleDescription() != "detects token leaks" {
		t.Fatalf("rule text: got name=%q description=%q", got.GetRuleName(), got.GetRuleDescription())
	}
	if got.GetRuleAlertTruncation() != "max_alerts" {
		t.Fatalf("truncation: got %q", got.GetRuleAlertTruncation())
	}
}

func TestMarshalDetectionLogEntryEmitsRuleTagsSorted(t *testing.T) {
	t.Parallel()

	payload, err := MarshalDetectionLogEntry(DetectionLogInput{
		ScopeLogContext: testScopeLogContext(),
		Hit:             testHitEntry(),
		Event:           eventWithSecretArgv(),
		RuleTags: map[string]string{
			"severity": "info",
			"category": "self-test",
		},
	})
	if err != nil {
		t.Fatalf("marshal detection log: %v", err)
	}
	var got logv1beta1.DetectionLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal detection log: %v", err)
	}
	want := []string{"category:self-test", "severity:info"}
	if !slices.Equal(got.GetRuleTags(), want) {
		t.Fatalf("rule_tags: got %v, want %v", got.GetRuleTags(), want)
	}
}

func TestMarshalDetectionLogEntryOmitsEmptyRuleTags(t *testing.T) {
	t.Parallel()

	payload, err := MarshalDetectionLogEntry(DetectionLogInput{
		ScopeLogContext: testScopeLogContext(),
		Hit:             testHitEntry(),
		Event:           eventWithSecretArgv(),
	})
	if err != nil {
		t.Fatalf("marshal detection log: %v", err)
	}
	var got logv1beta1.DetectionLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal detection log: %v", err)
	}
	if len(got.GetRuleTags()) != 0 {
		t.Fatalf("rule_tags: got %v, want empty", got.GetRuleTags())
	}
}

func TestMarshalDetectionLogEntryRuleTagsEdgeCases(t *testing.T) {
	t.Parallel()

	payload, err := MarshalDetectionLogEntry(DetectionLogInput{
		ScopeLogContext: testScopeLogContext(),
		Hit:             testHitEntry(),
		Event:           eventWithSecretArgv(),
		RuleTags: map[string]string{
			"zeta":       "last",
			"alpha":      "first",
			"mid":        "middle",
			"with:colon": "v", // delimiter collision: keys may contain ":"
			"empty":      "",  // empty value rendered as "key:"
		},
	})
	if err != nil {
		t.Fatalf("marshal detection log: %v", err)
	}
	var got logv1beta1.DetectionLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal detection log: %v", err)
	}
	// slices.Sort orders by joined "k:v" string lexicographically.
	want := []string{
		"alpha:first",
		"empty:",
		"mid:middle",
		"with:colon:v",
		"zeta:last",
	}
	if !slices.Equal(got.GetRuleTags(), want) {
		t.Fatalf("rule_tags: got %v, want %v", got.GetRuleTags(), want)
	}
}

func TestMarshalDetectionLogEntryStampsLogTypeAndVersions(t *testing.T) {
	t.Parallel()

	payload, err := MarshalDetectionLogEntry(DetectionLogInput{
		ScopeLogContext: testScopeLogContext(),
		Hit:             testHitEntry(),
		Event:           eventWithSecretArgv(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got logv1beta1.DetectionLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.GetLogType() != logtype.Detection.Wire() {
		t.Errorf("log_type: got %q, want %q", got.GetLogType(), logtype.Detection.Wire())
	}
	if got.GetServiceName() != "cicd-sensor" {
		t.Errorf("service_name: got %q, want %q", got.GetServiceName(), "cicd-sensor")
	}
	if got.GetSchemaVersion() != "v1" {
		t.Errorf("schema_version: got %q, want %q", got.GetSchemaVersion(), "v1")
	}
	if got.GetServiceVersion() != version.Current {
		t.Errorf("service_version: got %q, want %q", got.GetServiceVersion(), version.Current)
	}
}
