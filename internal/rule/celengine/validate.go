// validate.go: cel.ASTValidator and cel.StaticOptimizer passes that run
// during compile. The validators are registered in env.go through
// cel.ASTValidators (run after type-check) or invoked explicitly from
// env.Compile (listReferenceValidator runs before string normalization
// so list diagnostics aren't swallowed by literal rewrites).
//
// Validator inventory:
//   - denyCallValidator (single-event): block `matches`, `size`, all
//     arithmetic / index operators. Rules should be predicate-only;
//     arithmetic and regex are footguns we don't want in the rule
//     corpus today.
//   - denyCallValidator (correlation): subset of the above. Index is
//     allowed because `rule["id"]` uses it, and `+` is allowed for
//     aggregating rule hit counts, including presence-bit sums across
//     primitive rules.
//   - inIPRangeValidator: confirm the CIDR argument to inIpRange is a
//     literal string and parses. Variable CIDR is rejected because the
//     current binding parses on every call (see inIPRangeBinding); we'd
//     rather catch typos at rule-load than at first event.
//   - correlationReferenceValidator: confirm correlation refs use the
//     `rule.X` / `rule["X"]` forms; correlation_compile.go relies on
//     that shape to rewrite to canonical ids.
//   - listReferenceValidator: confirm every `list.<name>` points at a
//     declared predefined list. The list table is supplied per Compile
//     call (rules use scope-local lists), so this is not an env-level
//     validator.

package celengine

import (
	"fmt"
	"net"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
)

// denyCallValidator rejects calls whose function name is in `forbidden`.
// One instance is registered for single-event rules and another for
// correlation rules with a tighter blocklist; both use the same Validate
// implementation.
type denyCallValidator struct {
	name      string
	forbidden map[string]struct{}
}

func newDenyCallValidator() cel.ASTValidator {
	// Single-event rules allow boolean logic, field access, `exists`, and
	// declared helpers. Regex, arithmetic, size, and direct indexing are out.
	return denyCallValidator{
		name: "cicd_sensor.validator.deny_calls",
		forbidden: denyCallSet("matches", "size",
			operators.Add, operators.Subtract, operators.Multiply, operators.Divide, operators.Modulo,
			operators.Index, operators.OptIndex,
		),
	}
}

func newCorrelationDenyCallValidator() cel.ASTValidator {
	// `+` is allowed for correlation-level count aggregation. Rule authors can
	// add raw total_count values, or clamp each count to 0/1 first
	// (`total_count >= 1 ? 1 : 0`) to count unique categories. Other
	// arithmetic, regex, and size stay out.
	return denyCallValidator{
		name: "cicd_sensor.validator.correlation_deny_calls",
		forbidden: denyCallSet("matches", "size",
			operators.Subtract, operators.Multiply, operators.Divide, operators.Modulo,
		),
	}
}

func denyCallSet(ops ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(ops))
	for _, op := range ops {
		set[op] = struct{}{}
	}
	return set
}

func (v denyCallValidator) Name() string {
	return v.name
}

func (v denyCallValidator) Validate(_ *cel.Env, _ cel.ValidatorConfig, a *celast.AST, iss *cel.Issues) {
	root := celast.NavigateAST(a)
	for _, call := range celast.MatchDescendants(root, celast.KindMatcher(celast.CallKind)) {
		name := call.AsCall().FunctionName()
		if _, ok := v.forbidden[name]; ok {
			iss.ReportErrorAtID(call.ID(), "disallowed CEL call %q", name)
		}
	}
}

type inIPRangeValidator struct{}

func newInIPRangeValidator() cel.ASTValidator {
	return inIPRangeValidator{}
}

func (inIPRangeValidator) Name() string {
	return "cicd_sensor.validator.in_ip_range"
}

func (inIPRangeValidator) Validate(_ *cel.Env, _ cel.ValidatorConfig, a *celast.AST, iss *cel.Issues) {
	root := celast.NavigateAST(a)
	for _, call := range celast.MatchDescendants(root, celast.FunctionMatcher("inIpRange")) {
		args := call.AsCall().Args()
		if len(args) != 2 {
			iss.ReportErrorAtID(call.ID(), "inIpRange requires exactly 2 arguments")
			continue
		}
		if args[1].Kind() != celast.LiteralKind {
			continue
		}
		cidr, ok := args[1].AsLiteral().Value().(string)
		if !ok {
			iss.ReportErrorAtID(args[1].ID(), "inIpRange CIDR argument must be a string")
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			iss.ReportErrorAtID(args[1].ID(), "invalid CIDR literal %q", cidr)
		}
	}
}

type correlationReferenceValidator struct{}

func newCorrelationReferenceValidator() cel.ASTValidator {
	return correlationReferenceValidator{}
}

func (correlationReferenceValidator) Name() string {
	return "cicd_sensor.validator.correlation_references"
}

// Correlations accept only `rule.<id>` and `rule["id"]` references. Dynamic or
// empty bracket keys are rejected because compile rewrites refs to canonical IDs.
func (correlationReferenceValidator) Validate(_ *cel.Env, _ cel.ValidatorConfig, a *celast.AST, iss *cel.Issues) {
	root := celast.NavigateAST(a)

	for _, callExpr := range celast.MatchDescendants(root, celast.KindMatcher(celast.CallKind)) {
		call := callExpr.AsCall()
		if !isRuleIndexCall(call) {
			continue
		}
		if _, err := correlationIndexLocalRuleID(callExpr); err != nil {
			iss.ReportErrorAtID(callExpr.ID(), "%s", err)
		}
	}
}

func validateListReferences(env *cel.Env, ast *cel.Ast, lists rule.PredefinedLists) error {
	optimizer, err := cel.NewStaticOptimizer(listReferenceValidator{lists: lists})
	if err != nil {
		return fmt.Errorf("build list reference validator: %w", err)
	}
	optimized, iss := optimizer.Optimize(env, ast)
	if iss != nil && iss.Err() != nil {
		return iss.Err()
	}
	if optimized == nil {
		return fmt.Errorf("validate list references: empty AST")
	}
	return nil
}

type listReferenceValidator struct {
	lists rule.PredefinedLists
}

func (v listReferenceValidator) Optimize(ctx *cel.OptimizerContext, ast *celast.AST) *celast.AST {
	celast.PostOrderVisit(ast.Expr(), celast.NewExprVisitor(func(expr celast.Expr) {
		if expr.Kind() != celast.SelectKind {
			return
		}
		sel := expr.AsSelect()
		if !isIdent(sel.Operand(), "list") {
			return
		}
		listName := sel.FieldName()
		if strings.TrimSpace(listName) == "" {
			ctx.ReportErrorAtID(expr.ID(), "list reference must use list.<name>")
			return
		}
		if _, exists := v.lists[listName]; !exists {
			ctx.ReportErrorAtID(expr.ID(), "undefined predefined list %q", listName)
		}
	}))
	return ast
}

func isIdent(expr celast.Expr, name string) bool {
	return expr.Kind() == celast.IdentKind && expr.AsIdent() == name
}
