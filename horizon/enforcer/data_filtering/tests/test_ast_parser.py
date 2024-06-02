from horizon.enforcer.data_filtering.rego_ast import (
    BooleanTerm,
    Call,
    CallTerm,
    NullTerm,
    Ref,
    RefTerm,
    Term,
    TermParser,
    NumberTerm,
    StringTerm,
    VarTerm,
)
from horizon.enforcer.data_filtering.schemas import CRTerm


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
