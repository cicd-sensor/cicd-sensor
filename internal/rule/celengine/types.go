// types.go: the public Go-side types CEL rules see, plus the compiled-
// program containers the agent evaluator passes around.
//
// Cache field invariant. The unexported *Val fields on CELProcess /
// CELAncestor mirror their exported counterparts. They are written
// exactly once per event by NewCELProcess / buildAncestorRefList
// (native_val.go) and read by the field-spec getters (native_field_spec.go).
// Test literals can leave them nil; the getters detect nil and build on
// the fly. No external caller should write these directly — go through
// NewCELProcess so the invariants stay enforced.

package celengine

import (
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
)

// CELProcess is exposed as the `process` variable on every event type.
// The pre-boxed *Val caches turn per-rule field reads into pointer
// loads instead of nativeToValue (allocating types.String/Int/...) calls.
type CELProcess struct {
	ExecPath  string
	Argv      []string
	Ancestors []CELAncestor

	// Populated by NewCELProcess. Nil = build on the fly (test path).
	execPathVal  ref.Val // types.String wrapping ExecPath
	argvVal      ref.Val // types.NewRefValList over pre-boxed Argv
	ancestorsVal ref.Val // types.NewRefValList over ancestorVal wrappers
}

// CELAncestor is one entry of process.ancestors, ordered newest parent
// first (immediate parent at index 0). Same caching pattern as
// CELProcess; populated by buildAncestorRefList in native_val.go.
type CELAncestor struct {
	ExecPath string
	Argv     []string

	execPathVal ref.Val // types.String wrapping ExecPath
	argvVal     ref.Val // types.NewRefValList over pre-boxed Argv
}

// CELInputEvent holds the variables for one event-specific CEL evaluation.
type CELInputEvent struct {
	Process CELProcess
	// process_exec.
	IsMemfd bool
	// network_connect.
	RemoteIP   string
	RemotePort int64
	Protocol   string
	Family     string
	// file_open / file_remove / unix_socket_connect.
	Path string
	// file_open.
	IsWrite bool
	IsRead  bool
	Flags   int64
	// file_remove / file_move / file_link.
	IsFolder     bool
	FromPath     string
	ToPath       string
	CreatedPath  string
	ExistingPath string
	IsHardlink   bool
	IsSymlink    bool
	// domain.
	Domain string
	Source string
	// unix_socket_connect.
	SocketType string
	IsAbstract bool
}

// CELRuleHit is exposed through correlation's `rule` map.
type CELRuleHit struct {
	TotalCount int64
}

// CompiledProgram bundles a cel.Program with the rule id and original
// source. RuleID is used as a diagnostics tag in error messages; Source
// is retained for tooling (cost reports, rule listings) that wants to
// display the human-written form rather than re-decoding the AST.
type CompiledProgram struct {
	RuleID  string
	Source  string
	program cel.Program
}

// CompiledException is one compiled exception clause plus provenance.
type CompiledException struct {
	Program          *CompiledProgram
	Source           string
	ModifierIdentity string
}

// CompiledRule is the hot-path-ready rule shape consumed by the agent evaluator.
type CompiledRule struct {
	CanonicalRuleID        rule.CanonicalRuleID
	Identity               rule.RuleIdentity
	HostRulesetRevision    string
	ProjectRulesetRevision string
	Action                 rule.RuleAction
	MaxAlerts              int
	CompiledCondition      *CompiledProgram
	Exceptions             []CompiledException
	StaticActivation       cel.Activation
	FeedHost               bool
	FeedProject            bool
}

// CompiledCorrelation is the hot-path-ready correlation rule shape.
type CompiledCorrelation struct {
	CanonicalRuleID          rule.CanonicalRuleID
	Identity                 rule.RuleIdentity
	ReferencedRuleIdentities map[string]rule.RuleIdentity
	HostRulesetRevision      string
	ProjectRulesetRevision   string
	Action                   rule.RuleAction
	MaxAlerts                int
	CompiledCondition        *CompiledProgram
	FeedHost                 bool
	FeedProject              bool
}

func (c CompiledCorrelation) NewActivation(hitCount func(rule.RuleIdentity) int64) cel.Activation {
	return newCorrelationActivation(hitCount, c.ReferencedRuleIdentities)
}

// EvalActivation runs the compiled program against a pre-built
// activation and returns the bool result. Rule conditions and exceptions
// must always evaluate to bool — anything else is a rule-author bug
// (e.g. forgetting the `==` and writing `process.exec_path` directly),
// and we surface that as an error rather than coercing.
//
// The cel.Program.Eval second return value (details) is intentionally
// dropped: we don't enable cel.OptTrackCost / cel.OptTrackState in the
// hot path, so details only carries diagnostics we already see through
// err. Avoiding the parameter avoids one ref.Val box per evaluation.
func (p *CompiledProgram) EvalActivation(act cel.Activation) (bool, error) {
	result, _, err := p.program.Eval(act)
	if err != nil {
		return false, err
	}
	boolResult, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression returned %T, want bool", result.Value())
	}
	return boolResult, nil
}
