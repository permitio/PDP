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


from enum import Enum
import json
from types import NoneType
from typing import Generic, List, TypeVar

from permit_datafilter.compile_api.schemas import (
    CRExpression,
    CRQuery,
    CompileResponse,
    CRTerm,
)


def indent_lines(s: str, indent_char: str = "\t", indent_level: int = 1) -> str:
    """
    indents all lines within a multiline string by an indent character repeated by a given indent level.
    e.g: indents all lines within a string by 3 tab (\t) characters (indent level 3).

    returns a new indented string.
    )
    """
    indent = indent_char * indent_level
    return "\n".join(["{}{}".format(indent, row) for row in s.splitlines()])


class QuerySet:
    """
    A queryset is a result of partial evaluation, creating a residual policy consisting
    of multiple queries (each query consists of multiple rego expressions).

    The query essentially outlines a set of conditions for the residual policy to be true.
    All the expressions of the query must be true (logical AND) in order for the query to evaluate to TRUE.

    You can roughly translate the query set into an SQL WHERE statement.

    Between each query of the queryset - there is a logical OR:
    Policy is true if query_1 OR query_2 OR ... OR query_n and query_i == (expr_i_1 AND ... AND expr_i_m).
    """

    def __init__(self, queries: list["Query"], support_modules: list):
        self._queries = queries
        self._support_modules = support_modules

    @classmethod
    def parse(cls, response: CompileResponse) -> "QuerySet":
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
        queries: List[CRQuery] = (
            [] if response.result.queries is None else response.result.queries.__root__
        )
        # TODO: parse support modules
        # modules: List[CRSupportModule] = (
        #     [] if response.result.support is None else response.result.support.__root__
        # )
        return cls([Query.parse(q) for q in queries], [])

    @property
    def queries(self) -> list["Query"]:
        return self._queries

    def __repr__(self):
        queries_str = "\n".join([indent_lines(repr(r)) for r in self._queries])
        return "QuerySet([\n{}\n])\n".format(queries_str)

    @property
    def always_false(self) -> bool:
        return len(self._queries) == 0

    @property
    def always_true(self) -> bool:
        return len(self._queries) > 0 and any(q.always_true for q in self._queries)

    @property
    def conditional(self) -> bool:
        return not self.always_false and not self.always_true


class Query:
    """
    A residual query is a result of partial evaluation.
    The query essentially outlines a set of conditions for the residual policy to be true.
    All the expressions of the query must be true (logical AND) in order for the query to evaluate to TRUE.
    """

    def __init__(self, expressions: list["Expression"]):
        self._expressions = expressions

    @classmethod
    def parse(cls, query: CRQuery) -> "Query":
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
        return cls([Expression.parse(e) for e in query.__root__])

    @property
    def expressions(self) -> list["Expression"]:
        return self._expressions

    @property
    def always_true(self) -> bool:
        """
        returns true if the query always evaluates to TRUE
        """
        return len(self._expressions) == 0

    def __repr__(self):
        exprs_str = "\n".join([indent_lines(repr(e)) for e in self._expressions])
        return "Query([\n{}\n])\n".format(exprs_str)


class Expression:
    """
    An expression roughly translate into one line of rego code.
    Typically a rego rule consists of multiple expressions.

    An expression is comprised of multiple terms (typically 3), where the first is an operator and the rest are operands.
    """

    def __init__(self, terms: list["Term"]):
        self._terms = terms

    @classmethod
    def parse(cls, data: CRExpression) -> "Expression":
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
        terms = data.terms
        if isinstance(terms, CRTerm):
            return cls([TermParser.parse(terms)])
        else:
            return cls([TermParser.parse(t) for t in terms])

    @property
    def operator(self) -> "Term":
        """
        returns the term that is the operator of the expression (typically the first term)
        """
        return self._terms[0]

    @property
    def operands(self) -> list["Term"]:
        """
        returns the terms that are the operands of the expression
        """
        return self._terms[1:]

    @property
    def terms(self) -> list["Term"]:
        """
        returns all the terms of the expression
        """
        return self._terms

    def __repr__(self):
        operands_str = ", ".join([repr(o) for o in self.operands])
        return "Expression({}, [{}])".format(repr(self.operator), operands_str)


T = TypeVar("T")


class TermType(str, Enum):
    NULL = "null"
    BOOLEAN = "boolean"
    NUMBER = "number"
    STRING = "string"
    VAR = "var"
    REF = "ref"
    CALL = "call"


class Term(Generic[T]):
    """
    a term is an atomic part of an expression (line of code).
    it is typically a literal (number, string, etc), a reference (variable) or an operator (e.g: "==" or ">").
    """

    def __init__(self, value: T):
        self.value = value

    @property
    def type(self) -> str:
        return NotImplementedError()

    @classmethod
    def parse(cls, data: T) -> "Term":
        return cls(data)

    def __repr__(self):
        return json.dumps(self.value)


class NullTerm(Term[NoneType]):
    @property
    def type(self) -> str:
        return TermType.NULL


class BooleanTerm(Term[bool]):
    @property
    def type(self) -> str:
        return TermType.BOOLEAN


class NumberTerm(Term[int | float]):
    @property
    def type(self) -> str:
        return TermType.NUMBER


class StringTerm(Term[str]):
    @property
    def type(self) -> str:
        return TermType.STRING


class VarTerm(Term[str]):
    def __repr__(self):
        return self.value

    @property
    def type(self) -> str:
        return TermType.VAR


class Ref:
    """
    represents a reference in OPA, which is a path to a document in the OPA document tree.
    when translating this into a boolean expression tree, a reference would typically translate into a variable.
    """

    def __init__(self, ref_parts: list[str]):
        self._parts = ref_parts

    @property
    def parts(self) -> list[str]:
        """
        the parts of the full path to the document, each part is a node in OPA document tree.
        """
        return self._parts

    @property
    def as_string(self) -> str:
        return str(self)  # calls __str__(self)

    def __str__(self):
        return ".".join(self._parts)


class RefTerm(Term[Ref]):
    """
    A term that represents an OPA reference, holds a Ref object as a value.
    """

    @property
    def type(self) -> str:
        return TermType.REF

    @classmethod
    def parse(cls, terms: list[dict]) -> "Term[Ref]":
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
    represents a function call expression inside OPA.
    """

    def __init__(self, func: Term, args: list[Term]):
        self._func = func
        self._args = args

    @property
    def func(self) -> Term:
        """
        a (ref)term that holds the reference to the name of the function that is acting on the arguments of the function call
        """
        return self._func

    @property
    def args(self) -> list[Term]:
        """
        the terms representing the arguments of the function call
        """
        return self._args

    def __str__(self):
        return "{}({})".format(self.func, ", ".join([str(arg) for arg in self.args]))


class CallTerm(Term[Call]):
    """
    A term that represents a function call Term, holds a Call object as a value.
    """

    @property
    def type(self) -> str:
        return TermType.CALL

    @classmethod
    def parse(cls, terms: list[dict]) -> Term[Call]:
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
