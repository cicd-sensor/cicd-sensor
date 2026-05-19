package celengine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
)

// CompileCorrelation compiles one correlation rule into a runnable
// CompiledCorrelation.
//
// Why the AST rewrite. Rule authors write `rule.X` or `rule["X"]` to
// reference another rule in the same rule set, where X is the bare
// rule_id. At runtime we cannot key the hit-count map by bare rule_id
// because the same id can appear in multiple rule sets and the same agent
// process can carry multiple sets concurrently. The canonical id is
// `<setIdentity>/<rule_id>`, but exposing that to authors would make
// rules brittle to set renames. We resolve it by rewriting every rule
// reference at compile time:
//
//	rule.foo            →  rule["set-a/foo"]
//	rule["foo"]         →  rule["set-a/foo"]
//
// After the rewrite, the program looks up directly into the canonical
// hit-count map (correlationActivation in correlation_activation.go) and
// never needs to know about set-local resolution. As a bonus we can
// also validate that every referenced rule actually exists in the
// enabled rule corpus, surfacing typos as compile errors rather than
// silent always-zero matches.
//
// The rewrite is implemented via cel.StaticOptimizer:
//   - correlationRuleRefCanonicalizer collects every `rule.X` / `rule["X"]`
//     node, then calls ctx.UpdateExpr to replace it in place with
//     ctx.NewCall(operators.Index, NewIdent("rule"), NewLiteral(canonical)).
//   - The visitor collects targets first and mutates afterwards so the
//     PostOrderVisit input remains stable while SetKindCase rewrites
//     nodes underneath it.
//
// Finally we sanity-check that at least one reference was resolved: a
// correlation with no rule refs (e.g. literal `true`) would compile but
// fire unconditionally, which is never the author's intent.
func (e *Env) CompileCorrelation(setIdentity string, candidate rule.Rule, enabledRuleCanonicalsByLocalID map[string]rule.CanonicalRuleID) (*CompiledCorrelation, error) {
	checked, iss := e.correlation.Compile(candidate.Condition)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if checked == nil {
		return nil, fmt.Errorf("compile correlation source: empty AST")
	}

	// CEL exposes AST rewrites through StaticOptimizer. This pass resolves
	// set-local correlation refs (`rule.X` / `rule["X"]`) into canonical
	// hit-store keys (`rule["<set>/<rule_id>"]`) before program construction.
	canonicalizer := newCorrelationRuleRefCanonicalizer(setIdentity, enabledRuleCanonicalsByLocalID)
	optimizer, err := cel.NewStaticOptimizer(canonicalizer)
	if err != nil {
		return nil, fmt.Errorf("build correlation optimizer: %w", err)
	}
	// Rewrite set-local rule refs into canonical hit-store keys.
	optimized, iss := optimizer.Optimize(e.correlation, checked)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if optimized == nil {
		return nil, fmt.Errorf("optimize correlation source: empty AST")
	}

	// A correlation condition must depend on at least one rule state. Plain
	// CEL expressions like `true` compile successfully, but they are not
	// meaningful correlations and would otherwise fire unconditionally.
	if !canonicalizer.hasResolvedReference {
		return nil, fmt.Errorf("correlation rule must reference at least one rule")
	}

	// The correlation itself is recorded under its canonical rule ID.
	identity := rule.RuleIdentity{RulesetID: setIdentity, RuleID: candidate.RuleID}
	canonicalRuleID := identity.CanonicalRuleID()
	// Build the executable program from the rewritten AST, while keeping the
	// original source string for diagnostics.
	prog, err := e.finalizeProgram(e.correlation, optimized, canonicalRuleID.String(), candidate.Condition)
	if err != nil {
		return nil, err
	}

	return &CompiledCorrelation{
		CanonicalRuleID:          canonicalRuleID,
		Identity:                 identity,
		ReferencedRuleIdentities: canonicalizer.referencedRuleIdentities,
		Action:                   candidate.Action,
		CompiledCondition:        prog,
	}, nil
}

// correlationRuleRefCanonicalizer implements cel.ASTOptimizer. It replaces every
// `rule.X` / `rule["X"]` reference in a correlation expression with
// `rule["<setIdentity>/X"]`, so the built program looks up the activation
// map by canonical rule ID. Invalid references (missing rule, correlation
// cycle) are reported via ctx.ReportErrorAtID so the static optimizer surfaces
// them as compile issues.
type correlationRuleRefCanonicalizer struct {
	setIdentity                        string
	enabledRuleCanonicalsByLocalRuleID map[string]rule.CanonicalRuleID
	referencedRuleIdentities           map[string]rule.RuleIdentity
	hasResolvedReference               bool
}

type correlationRuleRef struct {
	expr        celast.Expr
	localRuleID string
}

func newCorrelationRuleRefCanonicalizer(setIdentity string, enabledRuleCanonicalsByLocalID map[string]rule.CanonicalRuleID) *correlationRuleRefCanonicalizer {
	return &correlationRuleRefCanonicalizer{
		setIdentity:                        setIdentity,
		enabledRuleCanonicalsByLocalRuleID: enabledRuleCanonicalsByLocalID,
		referencedRuleIdentities:           make(map[string]rule.RuleIdentity),
	}
}

// Optimize walks the AST, validates each rule reference, and replaces it in
// place with the canonical-keyed form via ctx.UpdateExpr. Collecting expr
// targets first and mutating afterwards keeps the visitor input stable while
// SetKindCase is rewriting nodes underneath it.
func (r *correlationRuleRefCanonicalizer) Optimize(ctx *cel.OptimizerContext, a *celast.AST) *celast.AST {
	var targets []correlationRuleRef
	celast.PostOrderVisit(a.Expr(), celast.NewExprVisitor(func(expr celast.Expr) {
		ruleRef, isRuleRef, err := correlationRuleRefFromExpr(expr)
		if err != nil {
			ctx.ReportErrorAtID(expr.ID(), "%s", err.Error())
			return
		}
		if isRuleRef {
			targets = append(targets, ruleRef)
		}
	}))

	for _, ruleRef := range targets {
		canonical, exists := r.enabledRuleCanonicalsByLocalRuleID[ruleRef.localRuleID]
		if !exists {
			ctx.ReportErrorAtID(ruleRef.expr.ID(), "correlation reference %q does not exist in enabled rules for set %q", ruleRef.localRuleID, r.setIdentity)
			continue
		}
		r.hasResolvedReference = true
		r.referencedRuleIdentities[canonical.String()] = rule.RuleIdentity{
			RulesetID: r.setIdentity,
			RuleID:    ruleRef.localRuleID,
		}
		ctx.UpdateExpr(ruleRef.expr, ctx.NewCall(
			operators.Index,
			ctx.NewIdent("rule"),
			ctx.NewLiteral(types.String(canonical.String())),
		))
	}
	return a
}

func correlationRuleRefFromExpr(expr celast.Expr) (correlationRuleRef, bool, error) {
	switch expr.Kind() {
	case celast.SelectKind:
		// CEL represents `rule.foo` as a field selection.
		sel := expr.AsSelect()
		if !isRuleIdent(sel.Operand()) {
			return correlationRuleRef{}, false, nil
		}
		localRuleID := sel.FieldName()
		if strings.TrimSpace(localRuleID) == "" {
			return correlationRuleRef{}, true, errors.New(`correlation rule reference must use rule["<rule_id>"] or rule.<rule_id>`)
		}
		return correlationRuleRef{expr: expr, localRuleID: localRuleID}, true, nil
	case celast.CallKind:
		// CEL represents `rule["foo"]` as an index call.
		if !isRuleIndexCall(expr.AsCall()) {
			return correlationRuleRef{}, false, nil
		}
		localRuleID, err := correlationIndexLocalRuleID(expr)
		if err != nil {
			return correlationRuleRef{}, true, err
		}
		return correlationRuleRef{expr: expr, localRuleID: localRuleID}, true, nil
	}
	return correlationRuleRef{}, false, nil
}

func isRuleIndexCall(call celast.CallExpr) bool {
	if len(call.Args()) == 0 {
		return false
	}
	switch call.FunctionName() {
	case operators.Index, operators.OptIndex:
		return isRuleIdent(call.Args()[0])
	default:
		return false
	}
}

func isRuleIdent(expr celast.Expr) bool {
	return expr.Kind() == celast.IdentKind && expr.AsIdent() == "rule"
}

func correlationIndexLocalRuleID(expr celast.Expr) (string, error) {
	// `rule["x"]` is encoded as Index(rule, "x").
	call := expr.AsCall()
	args := call.Args()
	if len(args) != 2 {
		return "", errors.New(`correlation references must use rule["<rule_id>"] or rule.<rule_id>`)
	}

	if args[1].Kind() != celast.LiteralKind {
		return "", errors.New(`correlation rule_id must be a string literal`)
	}

	literal, ok := args[1].AsLiteral().Value().(string)
	if !ok || strings.TrimSpace(literal) == "" {
		return "", errors.New(`correlation rule_id must be a non-empty string literal`)
	}
	return literal, nil
}
