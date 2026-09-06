// native_provider.go: hand-coded types.Provider for cicd-sensor's owned
// CEL struct types (CELProcess / CELAncestor / CELRuleHit).
//
// Background. cel-go ships an "ext.NativeTypes" path that lets a host
// register a Go struct as a CEL type by passing reflect.Type. Under the
// hood it uses reflection both at compile time (FindStructFieldType) and
// every field access (cext converter functions call reflect.Value.FieldByName
// or similar). Profiling rule evaluation showed that the per-event hot
// path was dominated by:
//   - reflect.Value.Interface() calls in cext.NativeTypes' GetFrom
//   - types.NativeToValue boxing primitives into ref.Val (allocating
//     types.String / types.Int per access)
// These costs are O(rules × fields read per rule) per event, which scales
// poorly even at modest rule counts.
//
// This file replaces that path with hand-coded closures. Each field is
// described once by a fieldSpec (see native_field_spec.go) carrying a typed
// getter; registerStruct turns that into the types.FieldType cel-go's
// interpreter calls. The getter:
//   - Type-asserts to the concrete struct (no reflect)
//   - Returns a pre-built ref.Val cache when one was populated by
//     NewCELProcess / buildAncestorRefList (see native_val.go)
//   - Falls back to building the ref.Val on the fly so test code can
//     write `CELProcess{...}` literals without touching the cache
//
// Everything we don't own (stdlib type idents, primitive list/map types)
// delegates to a NewProtoRegistry base.

package celengine

import (
	"fmt"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// Type names exposed to CEL. They appear in `cel.ObjectType(...)`
// declarations in env.go, in compile-time error messages, and through
// FindStructType / FindStructFieldType results. They must stay stable
// because they leak into rule diagnostics.
const (
	celProcessTypeName  = "celengine.CELProcess"
	celAncestorTypeName = "celengine.CELAncestor"
	celRuleHitTypeName  = "celengine.CELRuleHit"
)

// Pre-built *types.Type instances so we hand back the same identity each
// time. cel-go's checker compares types by pointer in some paths; new'ing
// these per lookup would still work, but reusing them is cheaper and lets
// other files (native_val.go) reference them as the canonical type token.
var (
	celProcessType  = types.NewObjectType(celProcessTypeName)
	celAncestorType = types.NewObjectType(celAncestorTypeName)
	celRuleHitType  = types.NewObjectType(celRuleHitTypeName)
)

// provider is the CustomTypeProvider passed to both cel.Env values in
// env.go. It owns CELProcess / CELAncestor / CELRuleHit. All other type
// lookups (stdlib idents, primitive list types) are forwarded to base.
//
// Lookups go through structs[name] for the owned types and fall through
// to base for anything unknown; this is the standard composition pattern
// for cel-go custom providers (see cel-go cel/options.go: CustomTypeProvider).
//
// provider is constructed once per cel.Env and shared across the base and
// correlation envs. It is read-only after NewEnv returns, so concurrent
// lookups during rule compilation and evaluation are safe.
type provider struct {
	base    types.Provider
	structs map[string]*structInfo
}

// structInfo is the cached cel-go shape for one owned type. fieldNames is
// stored separately from fields so FindStructFieldNames does not have to
// recompute it on each call (cel-go's checker calls this during type
// validation and for diagnostic messages on unknown fields).
type structInfo struct {
	celType    *types.Type
	fields     map[string]*types.FieldType
	fieldNames []string
}

// newProvider builds the provider once per process. The base registry
// matters: we use NewProtoRegistry, not NewEmptyRegistry, because cel-go's
// stdlib registers built-in type idents (list, map, int, string, ...) into
// the registry it would have created internally. With an empty registry,
// type-checking `list.foo` fails at "undeclared reference to 'list'"
// instead of the expected "list does not have field 'foo'" diagnostic, and
// `cel.Variable("list", cel.DynType)` in env.go would compile but produce
// a confusing user-facing error.
func newProvider() (*provider, error) {
	base, err := types.NewProtoRegistry()
	if err != nil {
		return nil, fmt.Errorf("create base proto registry: %w", err)
	}
	p := &provider{
		base:    base,
		structs: make(map[string]*structInfo, 3),
	}
	registerStruct(p, celProcessTypeName, celProcessType, processFieldSpecs)
	registerStruct(p, celAncestorTypeName, celAncestorType, ancestorFieldSpecs)
	registerStruct(p, celRuleHitTypeName, celRuleHitType, ruleHitFieldSpecs)
	return p, nil
}

// registerStruct binds the typed fieldSpec[Arg] entries into the untyped
// types.FieldType.GetFrom signature cel-go's interpreter expects.
//
// The generic Arg parameter is load-bearing: it lets the closure perform
// `o.(Arg)` and forward the typed value directly to spec.get without an
// intermediate `var v Arg = o.(Arg)` local. If we had a non-generic
// helper that took `func(any)` we'd need either an interface conversion
// or a typed local; in both cases Go's escape analysis would notice that
// the address of the local could leave the closure and would heap-allocate
// it on every access. Generic monomorphization keeps the conversion on
// the stack: one alloc per Compile, zero per access.
//
// The `o.(Arg)` assertion panics on type mismatch. This is intentional:
// cel-go's interpreter only invokes GetFrom after FindStructFieldType
// returns a typed FieldType, so the only path that can hand `o` of the
// wrong type is a wiring bug in this package or a cel-go regression.
// Panicking surfaces those bugs at the call site (with a useful stack)
// rather than dribbling out a types.Err and continuing. Wrap the path
// with a tolerant fallback only if we ever expose a non-CEL caller; for
// now, every GetFrom path is reached from typed cel-go internals.
//
// `spec := spec` shadows the loop variable. Without it, the closure
// captures the loop variable by reference (Go < 1.22 semantics) and every
// closure ends up calling the *last* spec.get. Even on Go 1.22+ where
// the loop var is per-iteration, the explicit shadow documents the intent
// and survives a future Go version change.
func registerStruct[Arg any](p *provider, name string, ct *types.Type, specs []fieldSpec[Arg]) {
	fields := make(map[string]*types.FieldType, len(specs))
	fieldNames := make([]string, 0, len(specs))
	for _, spec := range specs {
		spec := spec
		fields[spec.name] = celField(spec.celType, func(o any) ref.Val {
			return spec.get(o.(Arg))
		})
		fieldNames = append(fieldNames, spec.name)
	}
	p.structs[name] = &structInfo{celType: ct, fields: fields, fieldNames: fieldNames}
}

// alwaysSet implements types.FieldType.IsSet. cel-go's `has(x.field)`
// macro is disabled at the env level (cel.ClearMacros in NewEnv), so this
// function should never be called in production. Returning true keeps the
// field discoverable for any in-process tooling that probes the type
// shape via reflection (rule editors, doc generators).
func alwaysSet(any) bool { return true }

// celField packages a typed accessor into the types.FieldType cel-go
// expects. GetFrom always returns (val, nil) because our getters do not
// observably fail — type assertion failures would panic earlier in
// spec.get, which is fine: cel-go is calling us with a value whose type
// it has already verified through the env's TypeProvider.
func celField(t *types.Type, get func(any) ref.Val) *types.FieldType {
	return &types.FieldType{
		Type:    t,
		IsSet:   alwaysSet,
		GetFrom: func(o any) (any, error) { return get(o), nil },
	}
}

// --- types.Provider interface ---
//
// Each method below either handles an owned type locally or delegates to
// the base proto registry. The pattern is intentional: callers (cel-go's
// checker and runtime) cannot tell our types apart from any proto type
// registered through the base, which keeps stdlib behaviour intact.

// EnumValue is forwarded because we own no enums. cel-go calls this for
// `EnumName.VALUE` lookups during type check.
func (p *provider) EnumValue(enumName string) ref.Val {
	return p.base.EnumValue(enumName)
}

// FindIdent is forwarded because we own no module-level idents. The
// stdlib `list`, `map`, etc. type idents come from the base registry.
func (p *provider) FindIdent(identName string) (ref.Val, bool) {
	return p.base.FindIdent(identName)
}

// FindStructType returns the *types.Type wrapped in a type-of-type
// (NewTypeTypeWithParam), matching what cel-go's checker expects when it
// resolves `Process` as a type expression rather than a value. The proto
// registry handles other type names.
func (p *provider) FindStructType(structType string) (*types.Type, bool) {
	if si, ok := p.structs[structType]; ok {
		return types.NewTypeTypeWithParam(si.celType), true
	}
	return p.base.FindStructType(structType)
}

// FindStructFieldNames is used by cel-go for diagnostics on unknown
// fields ("did you mean ...?") and by introspection tooling. We return
// the cached slice rather than building one per call.
func (p *provider) FindStructFieldNames(structType string) ([]string, bool) {
	if si, ok := p.structs[structType]; ok {
		return si.fieldNames, true
	}
	return p.base.FindStructFieldNames(structType)
}

// FindStructFieldType is the type-check entry point: for `process.argv`
// the checker asks for the field type so it can verify the surrounding
// expression. For owned types we always return ok = true to signal "this
// type is mine", so an unknown field on an owned type produces a clean
// "no such field" diagnostic instead of falling through to the proto
// registry's "no such message" error.
func (p *provider) FindStructFieldType(structType, fieldName string) (*types.FieldType, bool) {
	if si, ok := p.structs[structType]; ok {
		if ft, ok := si.fields[fieldName]; ok {
			return ft, true
		}
		return nil, false
	}
	return p.base.FindStructFieldType(structType, fieldName)
}

// NewValue is the construction entry point: cel-go would call this for
// `Process{exec_path: "..."}` literals in CEL source. We reject
// construction of owned types because rules should not synthesize event
// values — the agent supplies them through EventActivation. Returning an
// Err here turns into a clean compile-time error instead of a confusing
// runtime panic.
func (p *provider) NewValue(structType string, fields map[string]ref.Val) ref.Val {
	if _, ok := p.structs[structType]; ok {
		return types.NewErr("construction of %s is not supported", structType)
	}
	return p.base.NewValue(structType, fields)
}
