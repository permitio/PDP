# Rego policy structure
#
# Rego policies are defined using a relatively small set of types:
# modules, package and import declarations, rules, expressions, and terms.
# At their core, policies consist of rules that are defined by one or more expressions over documents available to the policy engine.
# The expressions are defined by intrinsic values (terms) such as strings, objects, variables, etc.
# Rego policies are typically defined in text files and then parsed and compiled by the policy engine at runtime.
#
# The parsing stage takes the text or string representation of the policy and converts it into an abstract syntax tree (AST)
# that consists of the types mentioned above. The AST is organized as follows:
# 	Module
# 	 |
# 	 +--- Package (Reference)
# 	 |
# 	 +--- Imports
# 	 |     |
# 	 |     +--- Import (Term)
# 	 |
# 	 +--- Rules
# 	       |
# 	       +--- Rule
# 	             |
# 	             +--- Head
# 	             |     |
# 	             |     +--- Name (Variable)
# 	             |     |
# 	             |     +--- Key (Term)
# 	             |     |
# 	             |     +--- Value (Term)
# 	             |
# 	             +--- Body
# 	                   |
# 	                   +--- Expression (Term | Terms | Variable Declaration)
# 	                         |
#                            +--- Term


import json
from types import NoneType
from typing import Any, Generic, Optional, TypeVar

from horizon.enforcer.data_filtering.schemas import CRTerm


def indent_string(s: str, indent_char: str = "\t", indent_level: int = 1):
    indent = indent_char * indent_level
    return ["{}{}".format(indent, row) for row in s.splitlines()]


class QuerySet:
    """
    A queryset is a result of partial evaluation, creating a residual policy consisting
    of multiple queries (each query consists of multiple rego expressions).

    The query essentially outlines a set of conditions for the residual policy to be true.
    All the expressions of the query must be true (logical AND) in order for the query to evaluate to TRUE.

    You can roughly translate the query set into an SQL WHERE statement.

    Between each query of the queryset - there is a logical OR.
    """

    def __init__(self, queries: list["Query"]):
        self.queries = queries

    @classmethod
    def parse(cls, queries: list):
        """
        example data:
        # queryset
        [
            # query (an array of expressions)
            [
                # expression (an array of terms)
                {
                    "index": 0,
                    "terms": [
                        ...
                    ]
                }
            ],
            ...
        ]
        """
        return cls([Query.parse(q) for q in queries])

    def __repr__(self):
        queries_str = "\n".join([indent_string(repr(r)) for r in self.queries])
        return "QuerySet([\n{}\n])\n".format(queries_str)


class Query:
    """
    A residual query is a result of partial evaluation.
    The query essentially outlines a set of conditions for the residual policy to be true.
    All the expressions of the query must be true (logical AND) in order for the query to evaluate to TRUE.
    """

    def __init__(self, expressions: list["Expression"]):
        self.expressions = expressions

    @classmethod
    def parse(cls, expressions: list):
        """
        example data:
        # query (an array of expressions)
        [
            # expression (an array of terms)
            {
                "index": 0,
                "terms": [
                    ...
                ]
            }
        ]
        """
        return cls([Expression.parse(e) for e in expressions])

    def __repr__(self):
        exprs_str = "\n".join([indent_string(repr(e)) for e in self.expressions])
        return "Query([\n{}\n])\n".format(exprs_str)


class Expression:
    """
    An expression roughly translate into one line of rego code.
    Typically a rego rule consists of multiple expressions.

    An expression is comprised of multiple terms (typically 3), where the first is an operator and the rest are operands.
    """

    def __init__(self, terms: list["Term"]):
        self.terms = terms

    @classmethod
    def parse(cls, data: dict):
        """
        example data:
        # expression
        {
            "index": 0,
            # terms
            "terms": [
                # first term is typically an operator (e.g: ==, !=, >, <, etc)
                # the operator will typically be a *reference* to a built in function.
                # for example the "equals" (or "==") operator (within OPA operators are called builtins) is actually the builtin function "eq()".
                {
                    "type": "ref",
                    "value": [
                        {
                            "type": "var",
                            "value": "eq"
                        }
                    ]
                },
                # rest of terms are typically operands
                {
                    "type": "ref",
                    "value": [
                        {
                            "type": "var",
                            "value": "input"
                        },
                        {
                            "type": "string",
                            "value": "resource"
                        },
                        {
                            "type": "string",
                            "value": "tenant"
                        }
                    ]
                },
                {
                    "type": "string",
                    "value": "default"
                }
            ]
        }
        """
        terms = data["terms"]
        if isinstance(terms, dict):
            return cls([TermParser.parse(terms)])
        return cls([TermParser.parse(t) for t in terms])

    @property
    def operator(self):
        """
        returns the term that is the operator of the expression (typically the first term)
        """
        return self.terms[0]

    @property
    def operands(self):
        """
        returns the terms that are the operands of the expression
        """
        return self.terms[1:]

    def __repr__(self):
        operands_str = ",".join([repr(o) for o in self.operands])
        return "Expression({}, [{}])".format(repr(self.operator), operands_str)


T = TypeVar("T")


class Term(Generic[T]):
    def __init__(self, value: T):
        self.value = value

    @classmethod
    def parse(cls, data: T):
        return cls(data)

    def __repr__(self):
        return json.dumps(self.value)


class NullTerm(Term[NoneType]):
    pass


class BooleanTerm(Term[bool]):
    pass


class NumberTerm(Term[int | float]):
    pass


class StringTerm(Term[str]):
    pass


class VarTerm(Term[str]):
    def __repr__(self):
        return self.value


class Ref:
    def __init__(self, ref_parts: list[str]):
        self._parts = ref_parts

    @property
    def parts(self):
        return self._parts

    @property
    def as_string(self):
        return str(self)

    def __str__(self):
        return ".".join(self._parts)


class RefTerm(Term[Ref]):
    @classmethod
    def parse(cls, terms: list[dict]):
        assert len(terms) > 0
        parsed_terms: list[Term] = [TermParser.parse(CRTerm(**t)) for t in terms]
        var_term = parsed_terms[0]
        # TODO: support more types of refs
        assert isinstance(
            var_term, VarTerm
        ), "first sub-term inside ref is not a variable"
        string_terms = parsed_terms[1:]  # might be empty
        # TODO: support more types of refs
        assert all(
            isinstance(t, StringTerm) for t in string_terms
        ), "ref parts are not string terms"
        ref_parts = [t.value for t in parsed_terms]
        return cls(Ref(ref_parts))

    def __repr__(self):
        return "Ref({})".format(self.value.as_string)


class Call:
    """
    represents a function call
    """

    def __init__(self, func: Term, args: list[Term]):
        self._func = func
        self._args = args

    @property
    def func(self):
        return self._func

    @property
    def args(self):
        return self._args

    def __str__(self):
        return "{}({})".format(self.func, ", ".join([str(arg) for arg in self.args]))


class CallTerm(Term[Call]):
    @classmethod
    def parse(cls, terms: list[dict]):
        assert len(terms) > 0
        parsed_terms: list[Term] = [TermParser.parse(CRTerm(**t)) for t in terms]
        func_term = parsed_terms[0]
        # TODO: support more types of refs
        assert isinstance(func_term, RefTerm), "first sub-term inside call is not a ref"
        arg_terms = parsed_terms[1:]  # might be empty
        return cls(Call(func_term, arg_terms))

    def __repr__(self):
        return "call:{}".format(str(self.value))


class TermParser:
    TERMS_BY_TYPE: dict[str, Term] = {
        "null": NullTerm,
        "boolean": BooleanTerm,
        "number": NumberTerm,
        "string": StringTerm,
        "var": VarTerm,
        "ref": RefTerm,
        "call": CallTerm,
        # "array": ArrayTerm,
        # "set": SetTerm,
        # "object": ObjectTerm,
        # "arraycomprehension": ArrayComprehensionTerm,
        # "setcomprehension": SetComprehensionTerm,
        # "objectcomprehension": ObjectComprehensionTerm,
    }

    @classmethod
    def parse(cls, data: CRTerm) -> Term:
        if data.type == "null":
            data.value = None
        klass = cls.TERMS_BY_TYPE[data.type]
        return klass.parse(data.value)
