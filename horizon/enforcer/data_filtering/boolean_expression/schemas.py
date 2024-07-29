from __future__ import annotations

from enum import Enum
from typing import Any, Optional, Union

from pydantic import BaseModel, Field, root_validator

LOGICAL_AND = "and"
LOGICAL_OR = "or"
LOGICAL_NOT = "not"
CALL_OPERATOR = "call"


class BaseSchema(BaseModel):
    class Config:
        orm_mode = True
        allow_population_by_field_name = True


class Variable(BaseSchema):
    """
    represents a variable in a boolean expression tree.

    if the boolean expression originated in OPA - this was originally a reference in the OPA document tree.
    """

    variable: str = Field(..., description="a path to a variable (reference)")


class Value(BaseSchema):
    """
    Represents a value (literal) in a boolean expression tree.
    Could be of any jsonable type: string, int, boolean, float, list, dict.
    """

    value: Any = Field(
        ..., description="a literal value, typically compared to a variable"
    )


class Expr(BaseSchema):
    operator: str = Field(..., description="the name of the operator")
    operands: list["Operand"] = Field(..., description="the operands to the expression")


class Expression(BaseSchema):
    """
    represents a boolean expression, comparised of logical operators (e.g: and/or/not) and comparison operators (e.g: ==, >, <)

    we translate OPA call terms to expressions, treating the operator as the function name and the operands as the args.
    """

    expression: Expr = Field(
        ...,
        description="represents a boolean expression, comparised of logical operators (e.g: and/or/not) and comparison operators (e.g: ==, >, <)",
    )


Operand = Union[Variable, Value, "Expression"]


class ResidualPolicyType(str, Enum):
    ALWAYS_ALLOW = "always_allow"
    ALWAYS_DENY = "always_deny"
    CONDITIONAL = "conditional"


class ResidualPolicyResponse(BaseSchema):
    type: ResidualPolicyType = Field(..., description="the type of the residual policy")
    condition: Optional["Expression"] = Field(
        None,
        description="an optional condition, exists if the type of the residual policy is CONDITIONAL",
    )
    raw: Optional[dict] = Field(
        None,
        description="raw OPA compilation result, provided for debugging purposes",
    )

    @root_validator
    def check_condition_exists_when_needed(cls, values: dict):
        type, condition = values.get("type"), values.get("condition", None)
        if (
            type == ResidualPolicyType.ALWAYS_ALLOW
            or type == ResidualPolicyType.ALWAYS_DENY
        ) and condition is not None:
            raise ValueError(
                f"invalid residual policy: a condition exists but the type is not CONDITIONAL, instead: {type}"
            )
        if type == ResidualPolicyType.CONDITIONAL and condition is None:
            raise ValueError(
                f"invalid residual policy: type is CONDITIONAL, but no condition is provided"
            )
        return values


Expr.update_forward_refs()
Expression.update_forward_refs()
ResidualPolicyResponse.update_forward_refs()
