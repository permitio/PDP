from permit_datafilter.rego_ast import parser as ast
from permit_datafilter.boolean_expression.schemas import (
    CALL_OPERATOR,
    Operand,
    ResidualPolicyResponse,
    ResidualPolicyType,
    Expression,
    Expr,
    Value,
    Variable,
    LOGICAL_AND,
    LOGICAL_OR,
)


def translate_opa_queryset(queryset: ast.QuerySet) -> ResidualPolicyResponse:
    """
    translates the Rego AST into a generic residual policy constructed as a boolean expression.

    this boolean expression can then be translated by plugins into various SQL and ORMs.
    """
    if queryset.always_false:
        return ResidualPolicyResponse(type=ResidualPolicyType.ALWAYS_DENY)

    if queryset.always_true:
        return ResidualPolicyResponse(type=ResidualPolicyType.ALWAYS_ALLOW)

    if len(queryset.queries) == 1:
        return ResidualPolicyResponse(
            type=ResidualPolicyType.CONDITIONAL,
            condition=translate_query(queryset.queries[0]),
        )

    queries = [query for query in queryset.queries if not query.always_true]

    if len(queries) == 0:
        # no not trival queries means always true
        return ResidualPolicyResponse(type=ResidualPolicyType.ALWAYS_ALLOW)

    # else, more than one query means there's a logical OR between queries
    return ResidualPolicyResponse(
        type=ResidualPolicyType.CONDITIONAL,
        condition=Expression(
            expression=Expr(
                operator=LOGICAL_OR,
                operands=[translate_query(query) for query in queries],
            )
        ),
    )


def translate_query(query: ast.Query) -> Expression:
    if len(query.expressions) == 1:
        return translate_expression(query.expressions[0])

    return Expression(
        expression=Expr(
            operator=LOGICAL_AND,
            operands=[
                translate_expression(expression) for expression in query.expressions
            ],
        )
    )


def translate_expression(expression: ast.Expression) -> Expression:
    if len(expression.terms) == 1 and expression.terms[0].type == ast.TermType.CALL:
        # this is a call expression
        return translate_call_term(expression.terms[0].value)

    if not isinstance(expression.operator, ast.RefTerm):
        raise ValueError(
            f"The operator in an expression must be a term of type ref, instead got type {expression.operator.type} and value {expression.operator.value}"
        )

    return Expression(
        expression=Expr(
            operator=expression.operator.value.as_string,
            operands=[translate_term(term) for term in expression.operands],
        )
    )


def translate_call_term(call: ast.Call) -> Expression:
    return Expression(
        expression=Expr(
            operator=CALL_OPERATOR,
            operands=[
                Expression(
                    expression=Expr(
                        operator=call.func,
                        operands=[translate_term(term) for term in call.args],
                    )
                )
            ],
        )
    )


def translate_term(term: ast.Term) -> Operand:
    if term.type in (
        ast.TermType.NULL,
        ast.TermType.BOOLEAN,
        ast.TermType.NUMBER,
        ast.TermType.STRING,
    ):
        return Value(value=term.value)

    if term.type == ast.TermType.VAR:
        return Variable(variable=term.value)

    if term.type == ast.TermType.REF and isinstance(term.value, ast.Ref):
        return Variable(variable=term.value.as_string)

    if term.type == ast.TermType.CALL and isinstance(term.value, ast.Call):
        return translate_call_term(term.value)

    raise ValueError(
        f"unable to translate term with type {term.type} and value {term.value}"
    )
