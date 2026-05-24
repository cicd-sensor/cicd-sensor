// Package celengine wires cel-go into cicd-sensor's rule evaluator.
//
// Architecture (one cel.Env per event type, shared TypeProvider):
//
//	NewEnv  ── builds two cel.Env values, sharing one *provider:
//	  • base         single-event rules (process_exec, file_open, ...);
//	                 exposes event variables, predefined `list.<name>`,
//	                 inIpRange, and the .exists macro.
//	  • correlation  exposes only `rule.<id>` / `rule["<id>"]` map access;
//	                 macros are off so refs stay rewriteable to canonical IDs.
//
//	*provider (native_provider.go)
//	  Custom types.Provider used by both envs. Replaces cel-go's
//	  cext.NativeTypes reflect path for CELProcess / CELAncestor / CELRuleHit.
//	  Per-field reads dispatch through pre-built closures with ~no overhead.
//
//	specializedExistsMacro (this file)
//	  Parse-time rewrite for three .exists shapes
//	  (list.X.exists(p, T.{endsWith,startsWith,contains}(p))) into a single
//	  Go-side any-match call (__hasAny{Suffix,Prefix,Substr}), skipping
//	  cel-go's comprehension interpreter dispatch entirely. Body shapes that
//	  do not match fall through to the standard comprehension expansion.
//
//	predefined_list.go
//	  traits.Lister for `list.<name>`. Stores pre-boxed ref.Val and embeds
//	  one reusable iterator so .exists / contains do not allocate per call.
//
// Hot-path activation lives in input.go (EventActivation pooled per
// goroutine); correlation activation in correlation_activation.go.
//
// Performance posture: cel-go's interpreter is reflection-heavy by default.
// We deliberately replace three paths that pprof flagged as hot:
//   - reflect-based field resolution (cext.NativeTypes → CustomTypeProvider)
//   - nativeToValue boxing on every primitive read (pre-boxed caches in
//     CELProcess / CELAncestor + types.* return values from EventActivation)
//   - comprehension dispatch for common list-scan idioms (the .exists macro)
package celengine

import (
	"fmt"
	"net"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/parser"
)

// Env is the entry point used by the agent evaluator and CLI tooling.
//
// It bundles two cel.Env values built from the same types.Provider so that
// CELProcess / CELAncestor / CELRuleHit have a single schema across the two
// rule shapes. We keep them separate because their variable surfaces and
// macro sets differ: single-event rules need event variables and the
// specialized .exists macro; correlation rules need the `rule` map and must
// not perform comprehension/macro expansion so AST rewrites in
// correlation_compile.go can replace `rule.X` refs with canonical IDs.
//
// Env is safe for concurrent Compile / EnvForType use. Per-rule evaluation
// state lives in *EventActivation and is goroutine-local; see input.go.
type Env struct {
	base        *cel.Env
	correlation *cel.Env
}

// NewEnv builds the single-event and correlation cel.Env values used across
// the agent and CLI rule tooling. Both share one *provider so type identity
// for CELProcess / CELAncestor / CELRuleHit is consistent.
//
// Option choices, with rationale:
//
//   - cel.ClearMacros() drops cel-go's stdlib macros (has, all, exists_one,
//     filter, map, optMap, optFlatMap). Only .exists is intentionally
//     re-introduced via specializedExistsMacro because that's the only
//     comprehension shape the rule corpus uses, and we want full control
//     over how it expands. Removing the rest narrows the rule surface and
//     prevents authors from writing constructs we have not perf-validated.
//
//   - cel.Macros(specializedExistsMacro()) installs the .exists rewrite.
//     See specializedExistsMacro for the AST surgery and fall-through rules.
//
//   - cel.CustomTypeProvider(provider) routes struct field reads through
//     hand-written closures instead of cel-go's reflect path. See
//     native_provider.go. provider also delegates stdlib type idents (list,
//     map, int, ...) to a NewProtoRegistry base so type-checking continues
//     to work normally.
//
//   - cel.Variable("list", cel.DynType) exposes the predefined list table
//     as a dynamic map. Concrete element types are validated separately by
//     listReferenceValidator (validate.go) so we get static "undefined
//     predefined list X" errors without baking the list schema into the env.
//
//   - inIpRange is a free function (not a method). The CIDR argument is
//     verified to be a string literal at validate time (newInIPRangeValidator)
//     so the runtime binding can assume valid input and skip per-call cidr
//     parsing of variables (we still parse the literal at runtime for now;
//     a future optimization can precompute the *net.IPNet on the literal).
//
//   - The __hasAny{Suffix,Prefix,Substr} functions are the targets the
//     .exists macro rewrites to. They are reachable by name if an author
//     hand-writes them in a rule, but their signature is fixed (string,
//     list<string>) and they perform a pure list scan — no privileged
//     work. The "__" prefix is a convention; we did not add a validator to
//     reject direct calls because the complexity was not worth the marginal
//     UX gain.
//
//   - cel.ASTValidators wires denyCallValidator (block matches/size/arith)
//     and inIPRangeValidator (literal-CIDR check). These run after type
//     check; see validate.go.
//
//   - cel.EagerlyValidateDeclarations(true) + cel.ExtendedValidations()
//     turn on cel-go's stricter declaration / type checks, surfacing
//     malformed rules at compile time rather than at first eval.
//
// The correlation env is intentionally minimal: macros are off (so
// correlationRuleRefCanonicalizer in correlation_compile.go can see the raw
// `rule.X` / `rule["X"]` AST nodes), and the only variable is the `rule`
// map keyed by canonical rule id. CELProcess / CELAncestor types are still
// registered through the shared provider but no variable exposes them; this
// keeps type lookups consistent in case future correlation rules expand
// scope.
func NewEnv() (*Env, error) {
	provider, err := newProvider()
	if err != nil {
		return nil, fmt.Errorf("create CEL type provider: %w", err)
	}
	base, err := cel.NewEnv(
		cel.ClearMacros(),
		cel.Macros(specializedExistsMacro()),
		cel.CustomTypeProvider(provider),
		cel.Variable("list", cel.DynType),
		cel.Function(
			"inIpRange",
			cel.Overload(
				"inIpRange_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(inIPRangeBinding),
			),
		),
		anyMatchFunction("__hasAnySuffix", strings.HasSuffix),
		anyMatchFunction("__hasAnyPrefix", strings.HasPrefix),
		anyMatchFunction("__hasAnySubstr", strings.Contains),
		cel.ASTValidators(newDenyCallValidator(), newInIPRangeValidator()),
		cel.EagerlyValidateDeclarations(true),
		cel.ExtendedValidations(),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}

	correlation, err := cel.NewEnv(
		cel.ClearMacros(),
		cel.CustomTypeProvider(provider),
		cel.Variable("rule", cel.MapType(cel.StringType, cel.ObjectType(celRuleHitTypeName))),
		cel.ASTValidators(newCorrelationDenyCallValidator(), newCorrelationReferenceValidator()),
		cel.EagerlyValidateDeclarations(true),
		cel.ExtendedValidations(),
	)
	if err != nil {
		return nil, fmt.Errorf("create correlation CEL environment: %w", err)
	}

	return &Env{base: base, correlation: correlation}, nil
}

// Compile runs the single-event compilation pipeline. The phases are:
//
//  1. EnvForType: extend the base env with the variables available for
//     the requested event type (e.g. is_memfd for ProcessExec, remote_ip
//     for NetworkConnect).
//  2. env.Compile: parse + type-check. Macros (only specializedExistsMacro)
//     run during parse, so the resulting AST may already contain
//     __hasAny{Suffix,Prefix,Substr} calls in place of comprehensions.
//     cel-go's ASTValidators (denyCallValidator, inIPRangeValidator) run
//     here too and turn into iss errors.
//  3. validateListReferences: ensure every `list.<name>` reference points
//     at a real predefined list. Run after the cel-go validators because
//     we want list-name diagnostics to be reported even if the rule has
//     other problems.
//  4. normalizeStringLiterals: rewrite string literals through the same
//     normalization the runtime applies to event values (NFC + lowercase),
//     so authors can write either case and matching works the same.
//  5. finalizeProgram: build a cel.Program with OptOptimize for
//     constant-folding and ahead-of-time constant evaluation.
//
// Returning *CompiledProgram instead of cel.Program lets callers carry the
// rule id and source string for diagnostics without re-wrapping at every
// callsite.
func (e *Env) Compile(ruleID string, eventType jobevent.Type, source string, lists rule.PredefinedLists) (*CompiledProgram, error) {
	env, err := e.EnvForType(eventType)
	if err != nil {
		return nil, err
	}

	ast, iss := env.Compile(source)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}

	if ast == nil {
		return nil, fmt.Errorf("compile %s: empty AST", ruleID)
	}
	if err := validateListReferences(env, ast, lists); err != nil {
		return nil, err
	}
	ast, err = normalizeStringLiterals(env, ast)
	if err != nil {
		return nil, err
	}

	return e.finalizeProgram(env, ast, ruleID, source)
}

func (e *Env) finalizeProgram(env *cel.Env, ast *cel.Ast, ruleID, source string) (*CompiledProgram, error) {
	prog, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("build CEL program: %w", err)
	}

	return &CompiledProgram{
		RuleID:  ruleID,
		Source:  source,
		program: prog,
	}, nil
}

// EnvForType returns a type-specific cel.Env extended with the variables
// available for the given event type. Exposed so sibling packages
// can compile expressions against the same variable schema
// without rebuilding the base env.
func (e *Env) EnvForType(eventType jobevent.Type) (*cel.Env, error) {
	var opts []cel.EnvOption

	// `process` is exposed across all event types: file_open and network
	// events also carry the originating process snapshot for lineage rules.
	opts = append(opts,
		cel.Variable("process", cel.ObjectType(celProcessTypeName)),
	)

	switch eventType {
	case jobevent.ProcessExec:
		// is_memfd flags strict memfd-backed exec. Ordinary tmpfs binaries
		// stay false; lineage and binary path use the common `process` value.
		opts = append(opts,
			cel.Variable("is_memfd", cel.BoolType),
		)
	case jobevent.NetworkConnect:
		// family reports the address family of the destination ("ipv4" or
		// "ipv6"), not the socket family. AF_INET6 sockets connecting to
		// an IPv4 destination via IPv4-mapped IPv6 surface as
		// family == "ipv4" + remote_ip in dotted-quad form, so dual-stack
		// happy-eyeballs is hidden from rule writers. AF_UNIX connects
		// surface through a separate event_type (unix_socket_connect),
		// not here.
		opts = append(opts,
			cel.Variable("remote_ip", cel.StringType),
			cel.Variable("remote_port", cel.IntType),
			cel.Variable("protocol", cel.StringType),
			cel.Variable("family", cel.StringType),
		)
	case jobevent.UnixSocketConnect:
		// path: filesystem path or @-prefixed abstract namespace name
		// (sun_path[0] == 0). socket_type: "stream" / "dgram" /
		// "seqpacket" mapped from kernel SOCK_*; "unknown" for exotic
		// types so rules using `socket_type == "stream"` stay readable.
		// is_abstract: convenience flag matching the abstract-namespace
		// rendering, since `path.startsWith("@")` works equivalently.
		opts = append(opts,
			cel.Variable("path", cel.StringType),
			cel.Variable("socket_type", cel.StringType),
			cel.Variable("is_abstract", cel.BoolType),
		)
	case jobevent.FileOpen:
		opts = append(opts,
			cel.Variable("path", cel.StringType),
			cel.Variable("is_write", cel.BoolType),
			cel.Variable("is_read", cel.BoolType),
			cel.Variable("flags", cel.IntType),
		)
	case jobevent.FileRemove:
		// path: filesystem-rooted path of the entry being removed.
		// is_folder: 1 when the hook source is security_inode_rmdir,
		// 0 when security_inode_unlink.
		opts = append(opts,
			cel.Variable("path", cel.StringType),
			cel.Variable("is_folder", cel.BoolType),
		)
	case jobevent.FileMove:
		// rename event: from_path = original location, to_path = new
		// location. Both filesystem-rooted (no mount cross-resolution).
		opts = append(opts,
			cel.Variable("from_path", cel.StringType),
			cel.Variable("to_path", cel.StringType),
		)
	case jobevent.FileLink:
		// created_path = newly created link / symlink directory entry.
		// existing_path = referenced entry (hardlink old_dentry walked
		// to absolute, symlink old_name resolved to absolute in
		// userspace). is_hardlink / is_symlink discriminate the hook.
		opts = append(opts,
			cel.Variable("created_path", cel.StringType),
			cel.Variable("existing_path", cel.StringType),
			cel.Variable("is_hardlink", cel.BoolType),
			cel.Variable("is_symlink", cel.BoolType),
		)
	case jobevent.Domain:
		// domain: lowercased query name with any trailing dot removed,
		// e.g. "example.com". source: observation channel — "dns" for
		// UDP/TCP port 53 today; future kernels add Varlink (nss-resolve)
		// and SNI.
		opts = append(opts,
			cel.Variable("domain", cel.StringType),
			cel.Variable("source", cel.StringType),
		)
	default:
		return nil, fmt.Errorf("unsupported event type %q", eventType)
	}

	env, err := e.base.Extend(opts...)
	if err != nil {
		return nil, fmt.Errorf("extend CEL environment: %w", err)
	}
	return env, nil
}

// specializedExistsMacro registers a receiver macro for `target.exists(var, body)`.
//
// cel-go's stdlib .exists expands to a comprehension at parse time: roughly
// a fold over the iter range that ORs the body into an accumulator until
// the accumulator is true. That fold is interpreted per element, which is
// where most of the hot-path CPU goes for rule bodies of the form
// list.X.exists(p, T.method(p)) — the body call is dispatched once per
// element through cel-go's interpreter (cel-go interpreter/interpretable.go
// evalFold → step.Eval).
//
// We replace the comprehension entirely for three common shapes:
//
//	list.X.exists(p, T.endsWith(p))   →  __hasAnySuffix(T, list.X)
//	list.X.exists(p, T.startsWith(p)) →  __hasAnyPrefix(T, list.X)
//	list.X.exists(p, T.contains(p))   →  __hasAnySubstr(T, list.X)
//
// The rewrite happens during parse, so cel-go's type checker, validators,
// and cost analyzer all see the function-call form — no comprehension, no
// per-element dispatch, no iterator allocation. Runtime work runs entirely
// in Go (anyMatchFunction below) on the pre-boxed []ref.Val backing the
// predefined list.
//
// Bodies that do not match one of these three shapes (==, &&, complex
// expressions, literal args, iter var on the receiver side, etc.) fall
// through to parser.MakeExists and behave exactly like the stdlib macro.
// See expandSpecializedExists for the full set of guard conditions.
//
// Receiver macros are documented in github.com/google/cel-go/parser/macro.go.
// arity 2 matches `target.exists(iterVar, body)`.
func specializedExistsMacro() parser.Macro {
	return parser.NewReceiverMacro(operators.Exists, 2, expandSpecializedExists)
}

// expandSpecializedExists implements the macro body. It inspects the
// already-parsed iterVar and body AST and decides whether to emit a
// specialized function call or fall through to the stdlib comprehension.
//
// AST shape we look for:
//
//	exists call args:  [0] iterVar (IdentKind)   e.g. `p`
//	                   [1] body                  must be CallKind
//
//	body:              call.IsMemberFunction()   true means `T.method(...)`
//	                   call.FunctionName()      one of endsWith/startsWith/contains
//	                   call.Target()            T (the string side)
//	                   call.Args()              must be exactly [iterVar]
//
// Failure on any of these → fall through (correctness over optimization).
// The exprReferencesIdent guard catches the degenerate case where T itself
// references iterVar (e.g. `list.exists(p, p.field.endsWith(p))`); rewriting
// that would dangle a reference to p outside the comprehension and fail
// type-check.
//
// We use eh.NewCall to synthesize the replacement node; this assigns a
// fresh AST id from the parser's id stream so subsequent passes (type
// check, validators, cost) see a well-formed AST.
func expandSpecializedExists(eh parser.ExprHelper, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	// Outer shape: `LIST.exists(iterVar, body)`. iterVar must be a plain
	// identifier and body must be a function call — anything else (literal
	// body, nested comprehension body, etc.) cannot match our three
	// target patterns.
	if len(args) == 2 && args[0].Kind() == ast.IdentKind && args[1].Kind() == ast.CallKind {
		iterVar := args[0].AsIdent()
		call := args[1].AsCall()
		// Body must be of the form `T.method(...)`. Binary operators
		// (`p == "x"`), logical NOT (`!p.contains("x")`), and free
		// function calls are not specializable and fall through here.
		if call.IsMemberFunction() {
			callArgs := call.Args()
			// Body must be exactly `T.method(iterVar)` — a single-arg
			// method whose sole argument is the iter var. Literal-arg
			// shapes (`a.contains("token")`) and multi-arg shapes
			// (`a.contains(a, a)`) fall through.
			if len(callArgs) == 1 &&
				callArgs[0].Kind() == ast.IdentKind &&
				callArgs[0].AsIdent() == iterVar {
				// Method name must map to one of __hasAny{Suffix,Prefix,Substr},
				// and the receiver T must not itself reference the iter var.
				// If T contained iterVar (e.g. `list.exists(p, p.x.endsWith(p))`),
				// our rewrite would lift T outside the comprehension and
				// dangle that reference — exprReferencesIdent walks T
				// defensively to catch this.
				if specFn, ok := specializedExistsFn(call.FunctionName()); ok &&
					!exprReferencesIdent(call.Target(), iterVar) {
					return eh.NewCall(specFn, call.Target(), target), nil
				}
			}
		}
	}
	// Any guard above unsatisfied → defer to the stdlib comprehension
	// expansion. Correctness preserved for all body shapes.
	return parser.MakeExists(eh, target, args)
}

// exprReferencesIdent reports whether e references name anywhere as an
// identifier. The walker covers the AST kinds that can legitimately appear
// inside the receiver expression of a method call (Ident / Select / Call /
// List / Map). LiteralKind and ComprehensionKind don't introduce iter-var
// references; the rest of the AST kinds are not reachable from a method
// receiver chain in our rule grammar.
//
// Why it matters: when we rewrite `list.exists(p, T.method(p))` to
// `__hasAnyXxx(T, list)`, T moves from inside the comprehension scope to
// outside it. If T itself references p (e.g. `p.x.endsWith(p)`), the
// rewrite produces `__hasAnyXxx(p.x, list)`, where p is now unbound —
// cel-go's type check would reject the rewritten AST. Falling back to the
// standard comprehension preserves semantics for these pathological cases
// at the cost of skipping the optimization (which is fine: no real rule
// uses this shape).
func exprReferencesIdent(e ast.Expr, name string) bool {
	if e == nil {
		return false
	}
	switch e.Kind() {
	case ast.IdentKind:
		return e.AsIdent() == name
	case ast.SelectKind:
		return exprReferencesIdent(e.AsSelect().Operand(), name)
	case ast.CallKind:
		c := e.AsCall()
		if c.IsMemberFunction() && exprReferencesIdent(c.Target(), name) {
			return true
		}
		for _, a := range c.Args() {
			if exprReferencesIdent(a, name) {
				return true
			}
		}
	case ast.ListKind:
		for _, el := range e.AsList().Elements() {
			if exprReferencesIdent(el, name) {
				return true
			}
		}
	case ast.MapKind:
		for _, entry := range e.AsMap().Entries() {
			kv := entry.AsMapEntry()
			if exprReferencesIdent(kv.Key(), name) || exprReferencesIdent(kv.Value(), name) {
				return true
			}
		}
	}
	return false
}

// specializedExistsFn maps a CEL string method to the __hasAny* overload
// id used by anyMatchFunction. Returning (_, false) means "no specialized
// form" so the macro should fall through to the stdlib comprehension.
func specializedExistsFn(method string) (string, bool) {
	switch method {
	case "endsWith":
		return "__hasAnySuffix", true
	case "startsWith":
		return "__hasAnyPrefix", true
	case "contains":
		return "__hasAnySubstr", true
	}
	return "", false
}

// anyMatchFunction declares one __hasAny* overload with the binding that
// the .exists rewrite targets.
//
// Behaviour: scan the list with the Go predicate (strings.HasSuffix,
// HasPrefix, or Contains). The list is the predefinedList from input.go
// which stores pre-boxed types.String elements, so list.Get(i) returns the
// cached ref.Val directly with no per-element allocation. The for-loop is
// indexed (types.Int(0)..size) rather than using traits.Iterator, because
// the iterator path would allocate one iterator per call even with our
// embedded-iter optimization — direct Get is cheaper for short lists where
// we don't need iteration state.
//
// The type-assertion fallbacks (return types.False on bad types) handle
// the case where the caller passes something other than a string + list of
// strings. cel-go's type checker should prevent that statically, but we
// stay defensive because this function is also reachable by direct call
// (the __ prefix is convention, not enforced).
func anyMatchFunction(name string, predicate func(string, string) bool) cel.EnvOption {
	return cel.Function(
		name,
		cel.Overload(
			name+"_string_list",
			[]*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
			cel.BoolType,
			cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
				target, ok := lhs.(types.String)
				if !ok {
					return types.False
				}
				list, ok := rhs.(traits.Lister)
				if !ok {
					return types.False
				}
				size, ok := list.Size().(types.Int)
				if !ok {
					return types.False
				}
				for i := types.Int(0); i < size; i++ {
					elem, ok := list.Get(i).(types.String)
					if !ok {
						continue
					}
					if predicate(string(target), string(elem)) {
						return types.True
					}
				}
				return types.False
			}),
		),
	)
}

// inIPRangeBinding parses the IP and CIDR at every call. The CIDR side is
// constrained to a literal by inIPRangeValidator (validate.go), so it
// would be safe to precompute the *net.IPNet at compile time and stash it
// in the AST; we don't yet because inIpRange is not hot enough to justify
// the AST surgery. If profiling shows it climbing, the path would be:
// inIPRangeValidator parses the literal, stashes the *net.IPNet, and
// rewrites the call to a unary binding that only parses the IP.
func inIPRangeBinding(lhs, rhs ref.Val) ref.Val {
	ip, ok := lhs.Value().(string)
	if !ok {
		return types.False
	}
	cidr, ok := rhs.Value().(string)
	if !ok {
		return types.False
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return types.False
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return types.False
	}
	return types.Bool(network.Contains(parsedIP))
}
