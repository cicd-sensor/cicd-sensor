package celengine

import (
	"fmt"
	"reflect"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// correlationActivation is the runtime counterpart of CompileCorrelation.
//
// Compile rewrote every `rule.X` reference in the AST to
// `rule["<set>/X"]`. At evaluation time the interpreter resolves the
// `rule` ident through ResolveName and then performs map lookups by
// canonical id. We satisfy that with a lazyRuleMap: each Find call
// invokes hitCount on the corresponding RuleIdentity, so total_count is
// always fresh and always scope-local (the caller owns the counter).
//
// We construct the lazyRuleMap on first ResolveName rather than in the
// constructor so the allocation is paid only when the correlation
// actually evaluates a rule reference. Most correlations have multiple
// references in the same expression and ResolveName fires once per
// evaluation (cel-go's interpreter caches the result via the activation
// chain), so we end up with one lazyRuleMap per evaluation.
type correlationActivation struct {
	hitCount            func(rule.RuleIdentity) int64
	ruleIdentitiesByKey map[string]rule.RuleIdentity
	ruleMap             *lazyRuleMap
}

func newCorrelationActivation(hitCount func(rule.RuleIdentity) int64, ruleIdentitiesByKey map[string]rule.RuleIdentity) cel.Activation {
	return &correlationActivation{
		hitCount:            hitCount,
		ruleIdentitiesByKey: ruleIdentitiesByKey,
	}
}

func (a *correlationActivation) Parent() cel.Activation {
	return nil
}

func (a *correlationActivation) ResolveName(name string) (any, bool) {
	if name != "rule" {
		return nil, false
	}
	if a.ruleMap == nil {
		a.ruleMap = &lazyRuleMap{
			hitCount:            a.hitCount,
			ruleIdentitiesByKey: a.ruleIdentitiesByKey,
		}
	}
	return a.ruleMap, true
}

// lazyRuleMap implements the correlation `rule` map. cel-go's interpreter
// requires traits.Mapper / traits.Indexer to read map keys; the rest of
// the interface (Iterator, Contains, Size, conversions) is implemented
// minimally because correlation expressions never use those forms — by
// validator design, the only legal access shape is `rule.<id>` /
// `rule["<id>"]`, which both come through Find.
//
// total_count is always fetched live through hitCount. We do NOT cache
// per evaluation because:
//   - The correlation activation is built once per evaluation and
//     discarded; caching across evals would race with the agent updating
//     the counter.
//   - The hit count is a simple atomic-int read on the agent side, so
//     fetching it on every reference is cheap relative to the surrounding
//     interpreter overhead.
//
// Unknown rule ids resolve to CELRuleHit{} (total_count == 0). This is
// safe because the compile-time canonicalizer rejected typos, so an
// unknown key here implies the rule was disabled or deleted between
// compile and evaluation — treating it as "never fired" matches author
// intent.
type lazyRuleMap struct {
	hitCount            func(rule.RuleIdentity) int64
	ruleIdentitiesByKey map[string]rule.RuleIdentity
}

func (m *lazyRuleMap) Get(key ref.Val) ref.Val {
	val, _ := m.Find(key)
	return val
}

func (m *lazyRuleMap) Find(key ref.Val) (ref.Val, bool) {
	ruleKey, ok := key.Value().(string)
	if !ok {
		return types.ValOrErr(key, "rule key must be a string"), false
	}
	identity, found := m.ruleIdentitiesByKey[ruleKey]
	if !found {
		return newCELRuleHitVal(CELRuleHit{}), true
	}
	return newCELRuleHitVal(CELRuleHit{TotalCount: m.hitCount(identity)}), true
}

func (m *lazyRuleMap) Contains(key ref.Val) ref.Val {
	if _, ok := key.Value().(string); !ok {
		return types.ValOrErr(key, "rule key must be a string")
	}
	return types.NewErr("correlation rule map does not support containment tests")
}

func (m *lazyRuleMap) Size() ref.Val {
	// Correlation rules never iterate the rule map, so size is not meaningful.
	return types.Int(0)
}

func (m *lazyRuleMap) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, fmt.Errorf("lazyRuleMap cannot convert to %v", typeDesc)
}

func (m *lazyRuleMap) ConvertToType(typeValue ref.Type) ref.Val {
	return types.NewErr("lazyRuleMap cannot convert to %v", typeValue)
}

func (m *lazyRuleMap) Equal(other ref.Val) ref.Val {
	return types.False
}

func (m *lazyRuleMap) Type() ref.Type {
	return types.MapType
}

func (m *lazyRuleMap) Value() any {
	return nil
}

func (m *lazyRuleMap) Iterator() traits.Iterator {
	return nil
}
