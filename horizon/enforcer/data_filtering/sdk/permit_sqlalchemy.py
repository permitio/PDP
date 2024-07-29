from typing import Any, Callable, Dict, List, Tuple, Union, cast

import sqlalchemy as sa

# import Column, Table, and_, not_, or_, select
from sqlalchemy.orm import DeclarativeMeta, InstrumentedAttribute
from sqlalchemy.sql import Select
from sqlalchemy.sql.expression import BinaryExpression, ColumnOperators

from horizon.enforcer.data_filtering.boolean_expression.schemas import (
    CALL_OPERATOR,
    LOGICAL_AND,
    LOGICAL_NOT,
    LOGICAL_OR,
    Expression,
    Operand,
    ResidualPolicyResponse,
    ResidualPolicyType,
    Value,
    Variable,
)

Table = Union[sa.Table, DeclarativeMeta]
Column = Union[sa.Column, InstrumentedAttribute]
Condition = Union[BinaryExpression, ColumnOperators]


OperatorMap = Dict[str, Callable[[Column, Any], Condition]]

SUPPORTED_OPERATORS: OperatorMap = {
    "eq": lambda c, v: c == v,
    "ne": lambda c, v: c != v,
    "lt": lambda c, v: c < v,
    "gt": lambda c, v: c > v,
    "le": lambda c, v: c <= v,
    "ge": lambda c, v: c >= v,
}


def operator_to_sql(operator: str, column: Column, value: Any) -> Condition:
    if (operator_fn := SUPPORTED_OPERATORS.get(operator)) is not None:
        return operator_fn(column, value)
    raise ValueError(f"Unrecognised operator: {operator}")


def _get_table_name(t: Table) -> str:
    try:
        return t.__table__.name
    except AttributeError:
        return t.name


def verify_join_conditions(
    table: Table,
    reference_mapping: Dict[str, Column],
    join_conditions: Union[List[Tuple[Table, Condition]], None] = None,
):
    def column_table_name(c: Column) -> str:
        return cast(sa.Table, c.table).name

    def is_main_table_column(c: Column) -> bool:
        return column_table_name(c) == _get_table_name(table)

    required_joins = set(
        (
            column_table_name(column)
            for column in reference_mapping.values()
            if not is_main_table_column(column)
        )
    )

    if len(required_joins):
        if join_conditions is None:
            raise TypeError(f"to_query() is missing argument 'join_conditions'")
        else:
            missing_tables = required_joins.difference(
                set((t for t, _ in join_conditions))
            )
            if len(missing_tables):
                raise TypeError(
                    f"to_query() argument 'join_conditions' is missing mapping for tables: {repr(missing_tables)}"
                )


def to_query(
    filter: ResidualPolicyResponse,
    table: Table,
    reference_mapping: Dict[str, Column],
    join_conditions: Union[List[Tuple[Table, Condition]], None] = None,
) -> Select:
    select_all = cast(Select, sa.select(table))

    if filter.type == ResidualPolicyType.ALWAYS_ALLOW:
        return select_all

    if filter.type == ResidualPolicyType.ALWAYS_DENY:
        return select_all.where(False)

    verify_join_conditions(table, reference_mapping, join_conditions)

    def to_sql(expr: Expression):
        operator = expr.expression.operator
        operands = expr.expression.operands

        if operator == LOGICAL_AND:
            return sa.and_(*[to_sql(o) for o in operands])
        if operator == LOGICAL_OR:
            return sa.or_(*[to_sql(o) for o in operands])
        if operator == LOGICAL_NOT:
            return sa.not_(*[to_sql(o) for o in operands])
        if operator == CALL_OPERATOR:
            raise NotImplementedError("need to implement call() translation to sql")

        # otherwise, operator is a comparison operator
        variables = [o for o in operands if isinstance(o, Variable)]
        values = [o for o in operands if isinstance(o, Value)]

        if not (len(variables) == 1 and len(values) == 1):
            raise NotImplementedError(
                "need to implement support in more comparison operators"
            )

        variable_ref: str = variables[0].variable
        value: Any = values[0].value

        try:
            column = reference_mapping[variable_ref]
        except KeyError:
            raise KeyError(
                f"Residual variable does not exist in the reference mapping: {variable_ref}"
            )

        # the operator handlers here are the leaf nodes of the recursion
        return operator_to_sql(operator, column, value)

    query: Select = select_all.where(to_sql(filter.condition))

    if join_conditions:
        query = query.select_from(table)
        for join_table, predicate in join_conditions:
            query = query.join(join_table, predicate)

    return query
