from permit_datafilter.rego_ast.parser import (
    BooleanTerm,
    Call,
    CallTerm,
    Expression,
    NullTerm,
    Query,
    QuerySet,
    Ref,
    RefTerm,
    Term,
    TermParser,
    NumberTerm,
    StringTerm,
    VarTerm,
)
from permit_datafilter.compile_api.schemas import (
    CRTerm,
    CRExpression,
    CRQuery,
    CRQuerySet,
    CompileResponse,
)


def test_parse_null_term():
    t = CRTerm(**{"type": "null"})
    term: Term = TermParser.parse(t)
    assert isinstance(term, NullTerm)
    assert term.value == None


def test_parse_boolean_term():
    for val in [True, False]:
        t = CRTerm(**{"type": "boolean", "value": val})
        term: Term = TermParser.parse(t)
        assert isinstance(term, BooleanTerm)
        assert term.value == val
        isinstance(term.value, bool)


def test_parse_number_term():
    for val in [0, 2, 3.14]:
        t = CRTerm(**{"type": "number", "value": val})
        term: Term = TermParser.parse(t)
        assert isinstance(term, NumberTerm)
        assert term.value == val
        assert isinstance(term.value, int) or isinstance(term.value, float)


def test_parse_string_term():
    for val in ["hello", "world", ""]:
        t = CRTerm(**{"type": "string", "value": val})
        term: Term = TermParser.parse(t)
        assert isinstance(term, StringTerm)
        assert term.value == val
        assert isinstance(term.value, str)


def test_parse_var_term():
    t = CRTerm(**{"type": "var", "value": "eq"})
    term: Term = TermParser.parse(t)
    assert isinstance(term, VarTerm)
    assert term.value == "eq"
    assert isinstance(term.value, str)


def test_parse_simple_ref_term():
    simple_ref_term = {
        "type": "ref",
        "value": [
            {"type": "var", "value": "allowed"},
        ],
    }
    t = CRTerm(**simple_ref_term)
    term: Term = TermParser.parse(t)
    assert isinstance(term, RefTerm)
    assert isinstance(term.value, Ref)
    assert len(term.value.parts) == 1
    assert term.value.as_string == "allowed"


def test_parse_complex_ref_term():
    complex_ref_term = {
        "type": "ref",
        "value": [
            {"type": "var", "value": "input"},
            {"type": "string", "value": "resource"},
            {"type": "string", "value": "tenant"},
        ],
    }
    t = CRTerm(**complex_ref_term)
    term: Term = TermParser.parse(t)
    assert isinstance(term, RefTerm)
    assert isinstance(term.value, Ref)
    assert len(term.value.parts) == 3
    assert term.value.as_string == "input.resource.tenant"


def test_parse_call_term():
    call_term = {
        "type": "call",
        "value": [
            {"type": "ref", "value": [{"type": "var", "value": "count"}]},
            {
                "type": "ref",
                "value": [
                    {"type": "var", "value": "data"},
                    {"type": "string", "value": "partial"},
                    {"type": "string", "value": "example"},
                    {"type": "string", "value": "rbac4"},
                    {"type": "string", "value": "allowed"},
                ],
            },
        ],
    }
    t = CRTerm(**call_term)
    term: Term = TermParser.parse(t)
    assert isinstance(term, CallTerm)
    assert isinstance(term.value, Call)
    assert isinstance(term.value.func.value, Ref)
    assert term.value.func.value.as_string == "count"
    assert len(term.value.args) == 1
    assert isinstance(term.value.args[0].value, Ref)
    assert term.value.args[0].value.as_string == "data.partial.example.rbac4.allowed"


def test_parse_expression_eq():
    expr = {
        "index": 0,
        "terms": [
            {"type": "ref", "value": [{"type": "var", "value": "eq"}]},
            {
                "type": "ref",
                "value": [
                    {"type": "var", "value": "input"},
                    {"type": "string", "value": "resource"},
                    {"type": "string", "value": "tenant"},
                ],
            },
            {"type": "string", "value": "second"},
        ],
    }
    parsed_expr = CRExpression(**expr)
    assert parsed_expr.index == 0
    assert len(parsed_expr.terms) == 3
    expression = Expression.parse(parsed_expr)
    assert isinstance(expression.operator.value, Ref)
    assert expression.operator.value.as_string == "eq"
    assert len(expression.operands) == 2
    assert isinstance(expression.operands[0], RefTerm)
    assert expression.operands[0].value.as_string == "input.resource.tenant"
    assert isinstance(expression.operands[1], StringTerm)
    assert expression.operands[1].value == "second"


def test_parse_trivial_query():
    query = Query.parse(CRQuery(__root__=[]))
    assert len(query.expressions) == 0
    assert query.always_true


def test_parse_query():
    q = CRQuery(
        __root__=[
            {
                "index": 0,
                "terms": [
                    {"type": "ref", "value": [{"type": "var", "value": "gt"}]},
                    {
                        "type": "ref",
                        "value": [
                            {"type": "var", "value": "input"},
                            {"type": "string", "value": "resource"},
                            {"type": "string", "value": "attributes"},
                            {"type": "string", "value": "age"},
                        ],
                    },
                    {"type": "number", "value": 7},
                ],
            }
        ]
    )
    query = Query.parse(q)
    assert len(query.expressions) == 1
    assert not query.always_true

    expression = query.expressions[0]

    assert isinstance(expression.operator.value, Ref)
    assert expression.operator.value.as_string == "gt"
    assert len(expression.operands) == 2
    assert isinstance(expression.operands[0], RefTerm)
    assert expression.operands[0].value.as_string == "input.resource.attributes.age"
    assert isinstance(expression.operands[1], NumberTerm)
    assert expression.operands[1].value == 7


def test_parse_queryset_always_false():
    response = CompileResponse(**{"result": {}})
    queryset = QuerySet.parse(response)
    assert len(queryset.queries) == 0
    assert queryset.always_false
    assert not queryset.always_true
    assert not queryset.conditional


def test_parse_queryset_always_true():
    response = CompileResponse(
        **{
            "result": {
                "queries": [
                    [
                        {
                            "index": 0,
                            "terms": [
                                {
                                    "type": "ref",
                                    "value": [{"type": "var", "value": "eq"}],
                                },
                                {
                                    "type": "ref",
                                    "value": [
                                        {"type": "var", "value": "input"},
                                        {"type": "string", "value": "resource"},
                                        {"type": "string", "value": "tenant"},
                                    ],
                                },
                                {"type": "string", "value": "default"},
                            ],
                        }
                    ],
                    [],
                ]
            }
        }
    )
    queryset = QuerySet.parse(response)
    assert queryset.always_true
    assert not queryset.always_false
    assert not queryset.conditional


def test_parse_queryset_conditional():
    response = CompileResponse(
        **{
            "result": {
                "queries": [
                    [
                        {
                            "index": 0,
                            "terms": [
                                {
                                    "type": "ref",
                                    "value": [{"type": "var", "value": "eq"}],
                                },
                                {
                                    "type": "ref",
                                    "value": [
                                        {"type": "var", "value": "input"},
                                        {"type": "string", "value": "resource"},
                                        {"type": "string", "value": "tenant"},
                                    ],
                                },
                                {"type": "string", "value": "default"},
                            ],
                        }
                    ],
                    [
                        {
                            "index": 0,
                            "terms": [
                                {
                                    "type": "ref",
                                    "value": [{"type": "var", "value": "eq"}],
                                },
                                {
                                    "type": "ref",
                                    "value": [
                                        {"type": "var", "value": "input"},
                                        {"type": "string", "value": "resource"},
                                        {"type": "string", "value": "tenant"},
                                    ],
                                },
                                {"type": "string", "value": "second"},
                            ],
                        }
                    ],
                ]
            }
        }
    )
    queryset = QuerySet.parse(response)
    assert queryset.conditional
    assert not queryset.always_true
    assert not queryset.always_false

    assert len(queryset.queries) == 2

    q0 = queryset.queries[0]
    assert len(q0.expressions) == 1
    assert not q0.always_true

    expression = q0.expressions[0]

    assert isinstance(expression.operator.value, Ref)
    assert expression.operator.value.as_string == "eq"
    assert len(expression.operands) == 2
    assert isinstance(expression.operands[0], RefTerm)
    assert expression.operands[0].value.as_string == "input.resource.tenant"
    assert isinstance(expression.operands[1], StringTerm)
    assert expression.operands[1].value == "default"

    q1 = queryset.queries[1]
    assert len(q1.expressions) == 1
    assert not q1.always_true

    expression = q1.expressions[0]

    assert isinstance(expression.operator.value, Ref)
    assert expression.operator.value.as_string == "eq"
    assert len(expression.operands) == 2
    assert isinstance(expression.operands[0], RefTerm)
    assert expression.operands[0].value.as_string == "input.resource.tenant"
    assert isinstance(expression.operands[1], StringTerm)
    assert expression.operands[1].value == "second"
