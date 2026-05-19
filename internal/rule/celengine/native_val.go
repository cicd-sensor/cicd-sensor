// native_val.go: ref.Val adapters that let cel-go's runtime treat our
// owned Go structs as first-class values.
//
// Why we need wrappers. cel-go's interpreter expects every value flowing
// through it to satisfy ref.Val (Type / Value / Equal / ConvertToType /
// ConvertToNative). For primitives (string, int, bool) cel-go ships
// adapters in common/types (types.String etc.). For host structs the
// default path is cext.NativeTypes, which uses reflect to derive type
// identity and field access. We replaced field access with the hand-
// coded provider in native_provider.go, but list elements still need a
// minimal ref.Val wrapper so traits.Lister.Get(i) can return them with a
// stable Type() that matches what FindStructFieldType registered.
//
// Two wrappers (ancestorVal, ruleHitVal) instead of one generic wrapper
// keep the type assertions in fieldSpec[CELAncestor].get and the
// correlation rule map cheap: each wrapper exposes Value() returning the
// concrete struct so unwrapping is a single type assertion, not a chain
// of interface conversions.
//
// CELProcess does NOT have a wrapper because it is never a list element;
// it flows in through EventActivation.ResolveName as a *CELProcess
// (input.go) and the provider's exec_path/argv/ancestors closures handle
// it directly.

package celengine

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// Stable reflect.Type identities for ConvertToNative. Package vars so we
// do not call reflect.TypeOf on every conversion call (cold path, but
// cheap to fix and matches the existing *types.Type cache pattern above).
var (
	celAncestorReflectType = reflect.TypeOf(CELAncestor{})
	celRuleHitReflectType  = reflect.TypeOf(CELRuleHit{})
)

// ancestorVal wraps a CELAncestor as a ref.Val so list elements of
// process.ancestors have a stable Type() / Value() pair. The provider's
// GetFrom closure for `ancestor.exec_path` / `ancestor.argv` unwraps it
// with `o.(CELAncestor)` — see native_field_spec.go.
type ancestorVal struct{ v CELAncestor }

func (a ancestorVal) Type() ref.Type { return celAncestorType }
func (a ancestorVal) Value() any     { return a.v }

// Equal compares the logical fields (ExecPath, Argv) and ignores the
// unexported ref.Val cache fields. Without this, a CELAncestor built from
// a test literal (caches nil) would not compare equal to the same value
// returned through buildAncestorRefList (caches populated), even though
// the rule-visible state is identical. reflect.DeepEqual on CELAncestor
// would also walk the cache fields, so we compare field-by-field instead.
//
// Returning types.False on type mismatch matches cel-go built-in Equal
// (see String.Equal / Bool.Equal / baseList.Equal in common/types). The
// MaybeNoSuchOverloadErr convention is reserved for arithmetic/comparison
// operators (Add, Compare, etc.), not Equal.
//
// slices.Equal treats nil and len-0 slices as equal, matching CEL's
// list equality semantics — an ancestor with Argv: nil is equivalent to
// one with Argv: []string{}.
func (a ancestorVal) Equal(other ref.Val) ref.Val {
	o, ok := other.(ancestorVal)
	if !ok {
		return types.False
	}
	return types.Bool(a.v.ExecPath == o.v.ExecPath && slices.Equal(a.v.Argv, o.v.Argv))
}

func (a ancestorVal) ConvertToType(t ref.Type) ref.Val {
	if t == types.TypeType {
		return celAncestorType
	}
	if ot, ok := t.(*types.Type); ok && ot == celAncestorType {
		return a
	}
	return types.NewErr("type conversion not supported from %v to %v", celAncestorType, t)
}

// ConvertToNative accepts any reflect.Type that CELAncestor is assignable
// to: the concrete struct type and `interface{}` / `any`. Reads
// celAncestorReflectType.AssignableTo(t) instead of comparing equality so
// interface targets work without an extra branch.
func (a ancestorVal) ConvertToNative(t reflect.Type) (any, error) {
	if celAncestorReflectType.AssignableTo(t) {
		return a.v, nil
	}
	return nil, fmt.Errorf("native conversion not supported from CELAncestor to %v", t)
}

// ruleHitVal wraps a CELRuleHit as a ref.Val for correlation rule maps.
type ruleHitVal struct{ v CELRuleHit }

func (h ruleHitVal) Type() ref.Type { return celRuleHitType }
func (h ruleHitVal) Value() any     { return h.v }

func (h ruleHitVal) Equal(other ref.Val) ref.Val {
	o, ok := other.(ruleHitVal)
	if !ok {
		return types.False
	}
	return types.Bool(h.v == o.v)
}

func (h ruleHitVal) ConvertToType(t ref.Type) ref.Val {
	if t == types.TypeType {
		return celRuleHitType
	}
	if ot, ok := t.(*types.Type); ok && ot == celRuleHitType {
		return h
	}
	return types.NewErr("type conversion not supported from %v to %v", celRuleHitType, t)
}

func (h ruleHitVal) ConvertToNative(t reflect.Type) (any, error) {
	if celRuleHitReflectType.AssignableTo(t) {
		return h.v, nil
	}
	return nil, fmt.Errorf("native conversion not supported from CELRuleHit to %v", t)
}

// NewCELProcess constructs a CELProcess with its hot-field ref.Val caches
// (execPathVal, argvVal, ancestorsVal) populated. Callers in the agent
// hot path (evaluation/input.go) MUST use this constructor: the caches
// are the reason field access avoids per-rule allocation.
//
// Without the caches, each `process.exec_path` read in a CEL rule routes
// through types.NativeToValue(string) which allocates one types.String
// (cel-go common/types/provider.go:nativeToValue). With N rules sharing
// the same event, that's N allocations per event for a single field
// read. Pre-boxing once per event and serving the cached value via the
// fieldSpec get-closure folds those N allocations into one.
//
// Test code constructing CELProcess literals (e.g. `CELProcess{ExecPath:
// "/bin/bash"}`) leaves the caches nil; the fieldSpec getters check for
// nil and build the ref.Val on the fly. This keeps tests ergonomic
// without forcing them to call NewCELProcess.
func NewCELProcess(execPath string, argv []string, ancestors []CELAncestor) CELProcess {
	return CELProcess{
		ExecPath:     execPath,
		Argv:         argv,
		Ancestors:    ancestors,
		execPathVal:  types.String(execPath),
		argvVal:      buildStringRefList(argv),
		ancestorsVal: buildAncestorRefList(ancestors),
	}
}

// newCELAncestorVal / newCELRuleHitVal: explicit boxing helpers. The
// composite-literal form would also satisfy ref.Val via Go's implicit
// interface conversion, but the named helper marks the type→ref.Val
// transition at call sites (correlation_activation.go, buildAncestorRefList,
// test code).
func newCELAncestorVal(a CELAncestor) ref.Val { return ancestorVal{v: a} }
func newCELRuleHitVal(h CELRuleHit) ref.Val   { return ruleHitVal{v: h} }

// buildStringRefList returns a CEL list whose elements are already boxed
// as types.String.
//
// cel-go offers two list factories: NewStringList (backed by []string,
// where every Get(i) re-boxes via NativeToValue) and NewRefValList
// (backed by []ref.Val, where Get(i) returns the slot directly). We use
// NewRefValList so a .exists comprehension over process.argv iterates
// without allocating a types.String per element. The Argv slice is
// short-lived per event, so the one-time allocation cost of the []ref.Val
// is amortized across however many rules access process.argv that event.
func buildStringRefList(xs []string) ref.Val {
	if len(xs) == 0 {
		return types.NewRefValList(types.DefaultTypeAdapter, nil)
	}
	out := make([]ref.Val, len(xs))
	for i, s := range xs {
		out[i] = types.String(s)
	}
	return types.NewRefValList(types.DefaultTypeAdapter, out)
}

// buildAncestorRefList wraps each ancestor in ancestorVal with its
// hot-field caches pre-populated. The loop body writes a.execPathVal /
// a.argvVal directly instead of going through a helper that would take
// &a; that's deliberate. A helper accepting *CELAncestor would force the
// loop variable to escape to the heap (one alloc per ancestor per event)
// because Go's escape analysis assumes the helper might retain the
// pointer. The inline writes keep `a` on the stack — the wrapper
// ancestorVal copies the struct by value into its `v` field.
func buildAncestorRefList(xs []CELAncestor) ref.Val {
	if len(xs) == 0 {
		return types.NewRefValList(types.DefaultTypeAdapter, nil)
	}
	out := make([]ref.Val, len(xs))
	for i, a := range xs {
		a.execPathVal = types.String(a.ExecPath)
		a.argvVal = buildStringRefList(a.Argv)
		out[i] = newCELAncestorVal(a)
	}
	return types.NewRefValList(types.DefaultTypeAdapter, out)
}
