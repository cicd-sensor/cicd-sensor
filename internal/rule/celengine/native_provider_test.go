package celengine

import (
	"reflect"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

func TestProviderFindStructFieldType(t *testing.T) {
	t.Parallel()

	p, err := newProvider()
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	tests := []struct {
		structType string
		field      string
		wantType   *types.Type
		obj        any
		wantValue  ref.Val
	}{
		{celProcessTypeName, "exec_path", types.StringType, &CELProcess{ExecPath: "/bin/bash"}, types.String("/bin/bash")},
		{celAncestorTypeName, "exec_path", types.StringType, CELAncestor{ExecPath: "/usr/bin/curl"}, types.String("/usr/bin/curl")},
		{celRuleHitTypeName, "total_count", types.IntType, CELRuleHit{TotalCount: 7}, types.Int(7)},
	}

	for _, tt := range tests {
		t.Run(tt.structType+"."+tt.field, func(t *testing.T) {
			t.Parallel()

			ft, ok := p.FindStructFieldType(tt.structType, tt.field)
			if !ok {
				t.Fatalf("FindStructFieldType: not found")
			}
			if ft.Type != tt.wantType {
				t.Fatalf("Type: got %v, want %v", ft.Type, tt.wantType)
			}
			got, err := ft.GetFrom(tt.obj)
			if err != nil {
				t.Fatalf("GetFrom: %v", err)
			}
			gotRef, ok := got.(ref.Val)
			if !ok {
				t.Fatalf("GetFrom: returned %T, want ref.Val", got)
			}
			if eq := gotRef.Equal(tt.wantValue); eq != types.True {
				t.Fatalf("GetFrom value: got %v, want %v", gotRef, tt.wantValue)
			}
		})
	}
}

func TestProviderListFieldsReturnRefValList(t *testing.T) {
	t.Parallel()

	p, err := newProvider()
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	process := &CELProcess{Argv: []string{"sh", "-c", "echo"}}

	ft, ok := p.FindStructFieldType(celProcessTypeName, "argv")
	if !ok {
		t.Fatalf("argv field not found")
	}
	got, err := ft.GetFrom(process)
	if err != nil {
		t.Fatalf("GetFrom argv: %v", err)
	}
	list, ok := got.(traits.Lister)
	if !ok {
		t.Fatalf("argv: got %T, want traits.Lister", got)
	}
	if size := list.Size().(types.Int); size != 3 {
		t.Fatalf("argv size: got %d, want 3", size)
	}
	first := list.Get(types.Int(0))
	if first.Equal(types.String("sh")) != types.True {
		t.Fatalf("argv[0]: got %v, want \"sh\"", first)
	}
}

func TestProviderAncestorsListWrapsElements(t *testing.T) {
	t.Parallel()

	p, err := newProvider()
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	process := &CELProcess{Ancestors: []CELAncestor{{ExecPath: "/bin/bash"}}}

	ft, ok := p.FindStructFieldType(celProcessTypeName, "ancestors")
	if !ok {
		t.Fatalf("ancestors field not found")
	}
	got, err := ft.GetFrom(process)
	if err != nil {
		t.Fatalf("GetFrom ancestors: %v", err)
	}
	list, ok := got.(traits.Lister)
	if !ok {
		t.Fatalf("ancestors: got %T, want traits.Lister", got)
	}
	first := list.Get(types.Int(0))
	wrapper, ok := first.(ancestorVal)
	if !ok {
		t.Fatalf("ancestors[0]: got %T, want ancestorVal", first)
	}
	anc, ok := wrapper.Value().(CELAncestor)
	if !ok || anc.ExecPath != "/bin/bash" {
		t.Fatalf("ancestors[0].Value(): got %v, want CELAncestor{ExecPath:/bin/bash}", wrapper.Value())
	}
}

func TestProviderNewValueRejectsOwnedTypes(t *testing.T) {
	t.Parallel()

	p, err := newProvider()
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	got := p.NewValue(celProcessTypeName, nil)
	if !types.IsError(got) {
		t.Fatalf("NewValue: got %v, want error", got)
	}
}

func TestProviderFindStructFieldNames(t *testing.T) {
	t.Parallel()

	p, err := newProvider()
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	tests := []struct {
		structType string
		want       []string
	}{
		{celProcessTypeName, []string{"exec_path", "argv", "ancestors"}},
		{celAncestorTypeName, []string{"exec_path", "argv"}},
		{celRuleHitTypeName, []string{"total_count"}},
	}
	for _, tt := range tests {
		got, ok := p.FindStructFieldNames(tt.structType)
		if !ok {
			t.Fatalf("FindStructFieldNames(%s): not found", tt.structType)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("FindStructFieldNames(%s): got %v, want %v", tt.structType, got, tt.want)
		}
	}
}

func TestCelStructValValueReturnsUnderlying(t *testing.T) {
	t.Parallel()

	anc := CELAncestor{ExecPath: "/bin/sh"}
	wrapper := newCELAncestorVal(anc)
	got, ok := wrapper.Value().(CELAncestor)
	if !ok || got.ExecPath != "/bin/sh" {
		t.Fatalf("Value(): got %v, want CELAncestor", wrapper.Value())
	}
	if wrapper.Type() != celAncestorType {
		t.Fatalf("Type(): got %v, want %v", wrapper.Type(), celAncestorType)
	}
}

// ancestorVal.Equal must compare only the rule-visible fields (ExecPath,
// Argv) and ignore the unexported ref.Val caches. Two ancestors with the
// same logical content — one constructed as a test literal and one
// produced through buildAncestorRefList (with caches populated) — should
// be equal.
func TestAncestorValEqualIgnoresCacheFields(t *testing.T) {
	t.Parallel()

	literal := newCELAncestorVal(CELAncestor{
		ExecPath: "/bin/bash",
		Argv:     []string{"bash", "-c", "echo"},
	})
	withCaches := buildAncestorRefList([]CELAncestor{{
		ExecPath: "/bin/bash",
		Argv:     []string{"bash", "-c", "echo"},
	}}).(traits.Lister).Get(types.Int(0))

	if eq := literal.Equal(withCaches); eq != types.True {
		t.Fatalf("ancestorVal equality should ignore cache fields: got %v", eq)
	}
	if eq := withCaches.Equal(literal); eq != types.True {
		t.Fatalf("ancestorVal equality should be symmetric: got %v", eq)
	}
}

func TestAncestorValEqualRejectsCrossType(t *testing.T) {
	t.Parallel()

	v := newCELAncestorVal(CELAncestor{ExecPath: "/bin/bash"})
	if eq := v.Equal(types.String("/bin/bash")); eq != types.False {
		t.Fatalf("cross-type Equal should return False, got %v", eq)
	}
}

func TestAncestorValConvertToType(t *testing.T) {
	t.Parallel()

	v := newCELAncestorVal(CELAncestor{ExecPath: "/bin/bash"})

	if got := v.ConvertToType(types.TypeType); got != celAncestorType {
		t.Fatalf("ConvertToType(TypeType): got %v, want celAncestorType", got)
	}
	// Same-type conversion returns the receiver; check by Equal because
	// ancestorVal is not Go-comparable (CELAncestor.Argv is a slice).
	if got := v.ConvertToType(celAncestorType); got.Equal(v) != types.True {
		t.Fatalf("ConvertToType(celAncestorType): got %v, want self", got)
	}
	if got := v.ConvertToType(types.StringType); !types.IsError(got) {
		t.Fatalf("ConvertToType(StringType): got %v, want error", got)
	}
}

func TestAncestorValConvertToNative(t *testing.T) {
	t.Parallel()

	anc := CELAncestor{ExecPath: "/bin/bash"}
	v := newCELAncestorVal(anc)

	// Concrete type assignment.
	got, err := v.ConvertToNative(reflect.TypeOf(CELAncestor{}))
	if err != nil {
		t.Fatalf("ConvertToNative(CELAncestor): %v", err)
	}
	if got.(CELAncestor).ExecPath != "/bin/bash" {
		t.Fatalf("ConvertToNative value: got %v, want CELAncestor with /bin/bash", got)
	}

	// `any` is assignable from CELAncestor, must succeed.
	if _, err := v.ConvertToNative(reflect.TypeOf((*any)(nil)).Elem()); err != nil {
		t.Fatalf("ConvertToNative(any): %v", err)
	}

	// Unrelated type must error.
	if _, err := v.ConvertToNative(reflect.TypeOf("")); err == nil {
		t.Fatal("ConvertToNative(string): expected error, got nil")
	}
}

func TestRuleHitValEqual(t *testing.T) {
	t.Parallel()

	v := newCELRuleHitVal(CELRuleHit{TotalCount: 7})

	if eq := v.Equal(newCELRuleHitVal(CELRuleHit{TotalCount: 7})); eq != types.True {
		t.Fatalf("same value Equal: got %v, want True", eq)
	}
	if eq := v.Equal(newCELRuleHitVal(CELRuleHit{TotalCount: 8})); eq != types.False {
		t.Fatalf("different value Equal: got %v, want False", eq)
	}
	if eq := v.Equal(types.Int(7)); eq != types.False {
		t.Fatalf("cross-type Equal: got %v, want False", eq)
	}
}

func TestRuleHitValConvertToType(t *testing.T) {
	t.Parallel()

	v := newCELRuleHitVal(CELRuleHit{TotalCount: 1})

	if got := v.ConvertToType(types.TypeType); got != celRuleHitType {
		t.Fatalf("ConvertToType(TypeType): got %v, want celRuleHitType", got)
	}
	// ruleHitVal is Go-comparable (CELRuleHit has only TotalCount int64),
	// so direct equality works here.
	if got := v.ConvertToType(celRuleHitType); got != v {
		t.Fatalf("ConvertToType(celRuleHitType): got %v, want self", got)
	}
	if got := v.ConvertToType(types.IntType); !types.IsError(got) {
		t.Fatalf("ConvertToType(IntType): got %v, want error", got)
	}
}

func TestRuleHitValConvertToNative(t *testing.T) {
	t.Parallel()

	hit := CELRuleHit{TotalCount: 42}
	v := newCELRuleHitVal(hit)

	got, err := v.ConvertToNative(reflect.TypeOf(CELRuleHit{}))
	if err != nil {
		t.Fatalf("ConvertToNative(CELRuleHit): %v", err)
	}
	if got.(CELRuleHit).TotalCount != 42 {
		t.Fatalf("ConvertToNative value: got %v, want CELRuleHit{42}", got)
	}

	if _, err := v.ConvertToNative(reflect.TypeOf(0)); err == nil {
		t.Fatal("ConvertToNative(int): expected error, got nil")
	}
}

// NewCELProcess populates execPathVal, argvVal, ancestorsVal so the
// per-rule field readers (native_field_spec.go) return cached values
// without re-boxing primitives. These tests exercise the cache-hit path
// directly; existing tests built CELProcess literals which leave the
// caches nil and therefore only cover the fall-through branch.
func TestNewCELProcessPopulatesExecPathCache(t *testing.T) {
	t.Parallel()

	p := NewCELProcess("/bin/bash", nil, nil)
	if p.execPathVal == nil {
		t.Fatal("execPathVal should be non-nil after NewCELProcess")
	}
	if p.execPathVal.Equal(types.String("/bin/bash")) != types.True {
		t.Fatalf("execPathVal: got %v, want types.String(/bin/bash)", p.execPathVal)
	}
	// Field-spec lookup must return the cached identity, not a freshly
	// boxed value — observable via the closure returning the same ref.Val
	// the cache holds.
	got := processFieldSpecs[0].get(&p)
	if got != p.execPathVal {
		t.Fatalf("field getter returned a different ref.Val than the cache")
	}
}

func TestNewCELProcessPopulatesArgvCache(t *testing.T) {
	t.Parallel()

	p := NewCELProcess("/bin/sh", []string{"sh", "-c"}, nil)
	if p.argvVal == nil {
		t.Fatal("argvVal should be non-nil after NewCELProcess")
	}
	got := processFieldSpecs[1].get(&p)
	if got != p.argvVal {
		t.Fatalf("argv getter returned a different ref.Val than the cache")
	}
	list, ok := got.(traits.Lister)
	if !ok {
		t.Fatalf("argv: got %T, want traits.Lister", got)
	}
	if size := list.Size().(types.Int); size != 2 {
		t.Fatalf("argv size: got %d, want 2", size)
	}
	if list.Get(types.Int(0)).Equal(types.String("sh")) != types.True {
		t.Fatalf("argv[0]: got %v, want sh", list.Get(types.Int(0)))
	}
}

func TestNewCELProcessPopulatesAncestorsCache(t *testing.T) {
	t.Parallel()

	p := NewCELProcess("/usr/bin/python", nil, []CELAncestor{
		{ExecPath: "/bin/bash"},
	})
	if p.ancestorsVal == nil {
		t.Fatal("ancestorsVal should be non-nil after NewCELProcess")
	}
	got := processFieldSpecs[2].get(&p)
	if got != p.ancestorsVal {
		t.Fatalf("ancestors getter returned a different ref.Val than the cache")
	}
	list, ok := got.(traits.Lister)
	if !ok {
		t.Fatalf("ancestors: got %T, want traits.Lister", got)
	}
	first := list.Get(types.Int(0))
	if _, ok := first.(ancestorVal); !ok {
		t.Fatalf("ancestors[0]: got %T, want ancestorVal", first)
	}
}
