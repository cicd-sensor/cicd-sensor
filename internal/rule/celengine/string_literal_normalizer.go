package celengine

import (
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
)

// normalizeStringLiterals rewrites every string literal in the AST
// through rule.NormalizeString (NFC + lowercase), so a rule that says
// `"/BIN/BASH"` matches an event whose ExecPath is `/bin/bash` after the
// agent has normalized it. Without this pass, authors would have to
// remember to lowercase every literal — easy to forget, and silent when
// they do (the rule just never fires).
//
// We run as a cel.StaticOptimizer pass between validation and program
// construction. Earlier (during parse) would skip the validators; later
// (during eval) would re-normalize per call. Running on the post-check
// AST means the literal still has its checked type, so the rewritten
// node passes through cel-go's later passes unchanged.
//
// Only string-typed literal nodes are visited. Identifiers, field
// names, and function names are untouched: they are not literals and
// have their own case rules.
func normalizeStringLiterals(env *cel.Env, ast *cel.Ast) (*cel.Ast, error) {
	optimizer, err := cel.NewStaticOptimizer(stringLiteralNormalizer{})
	if err != nil {
		return nil, fmt.Errorf("build string literal normalizer: %w", err)
	}
	optimized, iss := optimizer.Optimize(env, ast)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if optimized == nil {
		return nil, fmt.Errorf("normalize string literals: empty AST")
	}
	return optimized, nil
}

type stringLiteralNormalizer struct{}

func (stringLiteralNormalizer) Optimize(ctx *cel.OptimizerContext, ast *celast.AST) *celast.AST {
	var targets []celast.Expr
	celast.PostOrderVisit(ast.Expr(), celast.NewExprVisitor(func(expr celast.Expr) {
		if expr.Kind() != celast.LiteralKind {
			return
		}
		literal, ok := expr.AsLiteral().Value().(string)
		if !ok {
			return
		}
		normalized := rule.NormalizeString(literal)
		if normalized == literal {
			return
		}
		targets = append(targets, expr)
	}))

	for _, target := range targets {
		literal := target.AsLiteral().Value().(string)
		ctx.UpdateExpr(target, ctx.NewLiteral(types.String(rule.NormalizeString(literal))))
	}
	return ast
}
