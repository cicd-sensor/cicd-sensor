package joblogs

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
)

func TestMarshalDetectionLogEntrySanitizesEventProcess(t *testing.T) {
	t.Parallel()

	payload, err := MarshalDetectionLogEntry(DetectionLogInput{
		ScopeLogContext: testScopeLogContext(),
		Hit:             testHitEntry(),
		Event:           eventWithSecretArgv(),
	})
	if err != nil {
		t.Fatalf("marshal detection log: %v", err)
	}

	var got logv1.JobDetectionLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal detection log: %v", err)
	}
	assertProtoEventProcessSanitized(t, got.GetEvent())
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

	var got logv1.JobDetectionLogEntry
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
