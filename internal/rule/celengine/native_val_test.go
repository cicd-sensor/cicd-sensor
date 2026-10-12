package celengine

import (
	"fmt"
	"reflect"
	"testing"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/traits"
)

// lineageAncestors builds a newest-first ancestor slice of the given depth
// with a fixed argv shape so allocation counts only depend on depth.
func lineageAncestors(depth int) []CELAncestor {
	out := make([]CELAncestor, depth)
	for i := range out {
		out[i] = CELAncestor{
			ExecPath: fmt.Sprintf("/usr/bin/proc-%d", i),
			Argv:     []string{"proc", "--flag", "value", "-c", "echo", "x"},
		}
	}
	return out
}

func TestNewCELProcessLineageDescendantsPerDepth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		depth int
	}{
		{name: "no_ancestors_gives_empty_list", depth: 0},
		{name: "single_ancestor_has_no_descendants", depth: 1},
		{name: "two_ancestors_root_sees_parent", depth: 2},
		{name: "max_tracked_depth_stays_consistent", depth: 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := NewCELProcess("/usr/bin/cat", nil, lineageAncestors(tt.depth))
			ancestors := processFieldSpecs[2].get(&p).(traits.Lister)
			if got := int(ancestors.Size().(types.Int)); got != tt.depth {
				t.Fatalf("ancestors size = %d, want %d", got, tt.depth)
			}
			for i := range tt.depth {
				boxed := ancestors.Get(types.Int(i)).(ancestorVal)
				want := fmt.Sprintf("/usr/bin/proc-%d", i)
				if got := boxed.Value().(CELAncestor).ExecPath; got != want {
					t.Fatalf("ancestors[%d].exec_path = %q, want %q (newest-first)", i, got, want)
				}
				assertDescendantsAreLineageSuffix(t, boxed.Value().(CELAncestor), i)
			}
		})
	}
}

// assertDescendantsAreLineageSuffix checks, recursively through the cached
// descendants lists, that ancestors[i] sees exactly ancestors[i-1 .. 0] in
// parent -> child order and never the current process.
func assertDescendantsAreLineageSuffix(t *testing.T, a CELAncestor, index int) {
	t.Helper()
	list := ancestorFieldSpecs[2].get(a).(traits.Lister)
	if a.descendantsVal == nil {
		t.Fatalf("ancestors[%d] descendants cache not populated", index)
	}
	want := make([]string, 0, index)
	for j := index - 1; j >= 0; j-- {
		want = append(want, fmt.Sprintf("/usr/bin/proc-%d", j))
	}
	if got := ancestorListExecPaths(list); !reflect.DeepEqual(got, want) {
		t.Fatalf("ancestors[%d].descendants = %v, want %v", index, got, want)
	}
	for j := range want {
		child := list.Get(types.Int(j)).(ancestorVal).Value().(CELAncestor)
		assertDescendantsAreLineageSuffix(t, child, index-1-j)
	}
}

func TestNewCELProcessSharedBoxedValuesStayEqual(t *testing.T) {
	t.Parallel()

	p := NewCELProcess("/usr/bin/cat", nil, lineageAncestors(3))
	ancestors := processFieldSpecs[2].get(&p).(traits.Lister)
	root := ancestors.Get(types.Int(2))
	viaAncestors := ancestors.Get(types.Int(1))
	viaDescendants := ancestorFieldSpecs[2].get(root.(ancestorVal).Value().(CELAncestor)).(traits.Lister).Get(types.Int(0))

	if eq := viaAncestors.Equal(viaDescendants); eq != types.True {
		t.Fatalf("same ancestor reached through two lists should be equal: got %v", eq)
	}
	native, err := viaDescendants.ConvertToNative(reflect.TypeOf(CELAncestor{}))
	if err != nil {
		t.Fatalf("ConvertToNative: %v", err)
	}
	if got := native.(CELAncestor).ExecPath; got != "/usr/bin/proc-1" {
		t.Fatalf("ConvertToNative exec_path = %q, want /usr/bin/proc-1", got)
	}
}

// Allocation growth must stay linear in depth. The bound is loose on
// purpose (the measured cost is ~15 allocs per level); a return to
// per-level re-boxing fails depth 16 by two orders of magnitude.
func TestNewCELProcessAllocationsGrowLinearly(t *testing.T) {
	tests := []struct {
		name  string
		depth int
	}{
		{name: "depth_0", depth: 0},
		{name: "depth_1", depth: 1},
		{name: "depth_2", depth: 2},
		{name: "depth_8", depth: 8},
		{name: "depth_16", depth: 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ancestors := lineageAncestors(tt.depth)
			argv := []string{"cat", "/etc/hostname"}
			allocs := testing.AllocsPerRun(50, func() {
				_ = NewCELProcess("/usr/bin/cat", argv, ancestors)
			})
			maxAllocs := float64(24*tt.depth + 48)
			if allocs > maxAllocs {
				t.Fatalf("NewCELProcess depth %d: %.0f allocs, want <= %.0f (linear in depth)", tt.depth, allocs, maxAllocs)
			}
		})
	}
}

func TestShallowFallbackPreservesLiteralDescendants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ancestor   CELAncestor
		wantFirst  []string
		wantNested []string
	}{
		{
			name:       "no_descendants_gives_empty_list",
			ancestor:   CELAncestor{ExecPath: "/bin/sh"},
			wantFirst:  []string{},
			wantNested: nil,
		},
		{
			name: "explicit_nested_literal_is_read_as_written",
			ancestor: CELAncestor{
				ExecPath: "/usr/bin/npm",
				Descendants: []CELAncestor{
					{ExecPath: "/bin/sh", Descendants: []CELAncestor{{ExecPath: "/usr/bin/curl"}}},
					{ExecPath: "/usr/bin/node"},
				},
			},
			wantFirst:  []string{"/bin/sh", "/usr/bin/node"},
			wantNested: []string{"/usr/bin/curl"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			list := ancestorFieldSpecs[2].get(tt.ancestor).(traits.Lister)
			if got := ancestorListExecPaths(list); !reflect.DeepEqual(got, tt.wantFirst) {
				t.Fatalf("descendants = %v, want %v", got, tt.wantFirst)
			}
			if tt.wantNested == nil {
				return
			}
			first := list.Get(types.Int(0)).(ancestorVal).Value().(CELAncestor)
			nested := ancestorFieldSpecs[2].get(first).(traits.Lister)
			if got := ancestorListExecPaths(nested); !reflect.DeepEqual(got, tt.wantNested) {
				t.Fatalf("nested descendants = %v, want %v", got, tt.wantNested)
			}
		})
	}
}

func BenchmarkNewCELProcessDepth(b *testing.B) {
	for _, depth := range []int{1, 4, 8, 11, 16} {
		ancestors := lineageAncestors(depth)
		argv := []string{"cc1", "-o", "foo.o", "foo.c"}
		b.Run(fmt.Sprintf("depth%d", depth), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = NewCELProcess("/usr/bin/cc1", argv, ancestors)
			}
		})
	}
}
