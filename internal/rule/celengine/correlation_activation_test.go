package celengine

import (
	"reflect"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/google/cel-go/common/types"
)

func TestCompiledCorrelationNewActivationResolvesRuleMap(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}
	compiled, err := env.CompileCorrelation("set-1", testCorrelationRule("corr", `rule["hit"].total_count >= 5`), map[string]rule.CanonicalRuleID{
		"hit": rule.RuleIdentity{RulesetID: "set-1", RuleID: "hit"}.CanonicalRuleID(),
	})
	if err != nil {
		t.Fatalf("compile correlation: %v", err)
	}

	activation := compiled.NewActivation(func(identity rule.RuleIdentity) int64 {
		if identity == (rule.RuleIdentity{RulesetID: "set-1", RuleID: "hit"}) {
			return 5
		}
		return 0
	})
	matched, err := compiled.CompiledCondition.EvalActivation(activation)
	if err != nil {
		t.Fatalf("eval correlation: %v", err)
	}
	if !matched {
		t.Fatal("expected correlation to match")
	}
}

func TestCompiledCorrelationNewActivationBelowThresholdDoesNotMatch(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}
	compiled, err := env.CompileCorrelation("set-1", testCorrelationRule("corr", `rule["hit"].total_count >= 5`), map[string]rule.CanonicalRuleID{
		"hit": rule.RuleIdentity{RulesetID: "set-1", RuleID: "hit"}.CanonicalRuleID(),
	})
	if err != nil {
		t.Fatalf("compile correlation: %v", err)
	}

	activation := compiled.NewActivation(func(identity rule.RuleIdentity) int64 {
		if identity == (rule.RuleIdentity{RulesetID: "set-1", RuleID: "hit"}) {
			return 4
		}
		return 0
	})
	matched, err := compiled.CompiledCondition.EvalActivation(activation)
	if err != nil {
		t.Fatalf("eval correlation: %v", err)
	}
	if matched {
		t.Fatal("expected correlation not to match")
	}
}

func TestCompiledCorrelationNewActivationMissingRuleZeroFills(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}
	compiled, err := env.CompileCorrelation("set-1", testCorrelationRule("corr", `rule["hit"].total_count >= 1`), map[string]rule.CanonicalRuleID{
		"hit": rule.RuleIdentity{RulesetID: "set-1", RuleID: "hit"}.CanonicalRuleID(),
	})
	if err != nil {
		t.Fatalf("compile correlation: %v", err)
	}

	activation := compiled.NewActivation(func(rule.RuleIdentity) int64 {
		return 0
	})
	matched, err := compiled.CompiledCondition.EvalActivation(activation)
	if err != nil {
		t.Fatalf("eval correlation: %v", err)
	}
	if matched {
		t.Fatal("expected missing rule count to zero-fill and not match")
	}
}

func TestCorrelationActivationLazyRuleMap(t *testing.T) {
	hitCount := func(identity rule.RuleIdentity) int64 {
		if identity == (rule.RuleIdentity{RulesetID: "set-1", RuleID: "hit-rule"}) {
			return 5
		}
		return 0
	}
	m := &lazyRuleMap{
		hitCount: hitCount,
		ruleIdentitiesByKey: map[string]rule.RuleIdentity{
			"set-1/hit-rule": {RulesetID: "set-1", RuleID: "hit-rule"},
		},
	}

	t.Run("Get_Hit", func(t *testing.T) {
		val := m.Get(types.String("set-1/hit-rule"))
		if types.IsError(val) {
			t.Fatalf("unexpected error: %v", val)
		}
		out, ok := val.Value().(CELRuleHit)
		if !ok {
			t.Fatalf("expected CELRuleHit, got %T", val.Value())
		}
		if out.TotalCount != 5 {
			t.Errorf("unexpected total_count: %+v", out)
		}
	})

	t.Run("Get_Miss_ZeroFill", func(t *testing.T) {
		val := m.Get(types.String("missing-rule"))
		out, ok := val.Value().(CELRuleHit)
		if !ok {
			t.Fatalf("expected CELRuleHit, got %T", val.Value())
		}
		if out.TotalCount != 0 {
			t.Errorf("expected zero-fill total_count, got %+v", out)
		}
	})

	t.Run("Find_Hit", func(t *testing.T) {
		val, found := m.Find(types.String("set-1/hit-rule"))
		if !found {
			t.Error("expected found=true")
		}
		out := val.Value().(CELRuleHit)
		if out.TotalCount != 5 {
			t.Errorf("expected 5, got %d", out.TotalCount)
		}
	})

	t.Run("Find_Miss_ZeroFill", func(t *testing.T) {
		val, found := m.Find(types.String("missing-rule"))
		if !found {
			t.Error("expected found=true for zero-fill semantics")
		}
		out := val.Value().(CELRuleHit)
		if out.TotalCount != 0 {
			t.Errorf("expected 0, got %d", out.TotalCount)
		}
	})

	t.Run("Contains_Unsupported", func(t *testing.T) {
		if res := m.Contains(types.String("set-1/hit-rule")); !types.IsError(res) {
			t.Errorf("expected error, got %v", res)
		}
	})

	t.Run("InvalidKeyType", func(t *testing.T) {
		val := m.Get(types.Int(123))
		if !types.IsError(val) {
			t.Error("expected error for non-string key")
		}
	})

	t.Run("ConvertToNative", func(t *testing.T) {
		_, err := m.ConvertToNative(reflect.TypeOf(map[string]any{}))
		if err == nil {
			t.Error("expected error for ConvertToNative")
		}
	})
}

func testCorrelationRule(ruleID, condition string) rule.Rule {
	return rule.Rule{
		RuleID:    ruleID,
		Type:      "correlation",
		Condition: condition,
		Action:    rule.RuleActionDetect,
	}
}
