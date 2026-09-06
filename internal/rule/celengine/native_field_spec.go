// native_field_spec.go: the static field tables registered with provider
// (native_provider.go). Each table lists one entry per CEL-accessible
// field on an owned struct, paired with a typed getter that returns the
// pre-boxed ref.Val cache when one exists, or builds on the fly when it
// does not.
//
// Keep field names in sync with rule corpus. They appear verbatim in
// production rules (`process.exec_path`, `ancestors[i].argv`, etc.) so
// renames here are breaking changes for rule authors.

package celengine

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// fieldSpec declares one CEL-accessible field on an owned struct.
//
// Arg is the concrete Go type the getter expects, after type assertion
// from the `any` value cel-go's interpreter hands the GetFrom closure:
//   - *T for CELProcess. The value flows in by pointer from
//     EventActivation.resolveLocal (input.go); using *T avoids copying
//     the ~80-byte struct on every field read.
//   - T for CELAncestor / CELRuleHit. They flow in as values unwrapped
//     from ancestorVal / ruleHitVal (native_val.go). Switching to *T
//     would force `&v` after the assertion, escaping v to the heap once
//     per access — one alloc per ancestor per rule per event, which
//     dominates pprof at any non-trivial rule count.
//
// get returns the cached ref.Val when populated by NewCELProcess /
// buildAncestorRefList, else builds on the fly. The cache lookup is the
// hot path; the fall-through exists so test code can write struct
// literals like `CELProcess{ExecPath: "..."}` without manually populating
// caches. Cache population is open-coded in native_val.go (not routed
// through this spec) to keep the same escape-analysis property for
// writes.
type fieldSpec[Arg any] struct {
	name    string
	celType *types.Type
	get     func(Arg) ref.Val
}

var processFieldSpecs = []fieldSpec[*CELProcess]{
	{
		name:    "exec_path",
		celType: types.StringType,
		get: func(p *CELProcess) ref.Val {
			if p.execPathVal != nil {
				return p.execPathVal
			}
			return types.String(p.ExecPath)
		},
	},
	{
		name:    "argv",
		celType: types.NewListType(types.StringType),
		get: func(p *CELProcess) ref.Val {
			if p.argvVal != nil {
				return p.argvVal
			}
			return buildStringRefList(p.Argv)
		},
	},
	{
		name:    "ancestors",
		celType: types.NewListType(celAncestorType),
		get: func(p *CELProcess) ref.Val {
			if p.ancestorsVal != nil {
				return p.ancestorsVal
			}
			return buildAncestorRefList(p.Ancestors)
		},
	},
}

var ancestorFieldSpecs = []fieldSpec[CELAncestor]{
	{
		name:    "exec_path",
		celType: types.StringType,
		get: func(a CELAncestor) ref.Val {
			if a.execPathVal != nil {
				return a.execPathVal
			}
			return types.String(a.ExecPath)
		},
	},
	{
		name:    "argv",
		celType: types.NewListType(types.StringType),
		get: func(a CELAncestor) ref.Val {
			if a.argvVal != nil {
				return a.argvVal
			}
			return buildStringRefList(a.Argv)
		},
	},
	{
		name:    "descendants",
		celType: types.NewListType(celAncestorType),
		get: func(a CELAncestor) ref.Val {
			if a.descendantsVal != nil {
				return a.descendantsVal
			}
			return buildAncestorRefList(a.Descendants)
		},
	},
}

// CELRuleHit has no cache: total_count is materialized per lookup by
// lazyRuleMap.Find with the latest hit count callback.
var ruleHitFieldSpecs = []fieldSpec[CELRuleHit]{
	{
		name:    "total_count",
		celType: types.IntType,
		get:     func(h CELRuleHit) ref.Val { return types.Int(h.TotalCount) },
	},
}
