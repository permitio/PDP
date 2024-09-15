from typing import Any, Callable, Dict, List, Optional, Tuple, Union, cast

import sqlalchemy as sa

from sqlalchemy.orm import DeclarativeMeta, InstrumentedAttribute
from sqlalchemy.sql import Select
from sqlalchemy.sql.expression import BinaryExpression, ColumnOperators

from permit_datafilter.boolean_expression.schemas import (
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
    join_conditions: List[Tuple[Table, Condition]] = [],
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
        if len(join_conditions) == 0:
            raise TypeError(
                f"You must call QueryBuilder.join(table, condition) to map residual references to other SQL tables"
            )
        else:
            provided_joined_tables = set(
                (_get_table_name(t) for t, _ in join_conditions)
            )
            missing_tables = required_joins.difference(provided_joined_tables)
            if len(missing_tables):
                raise TypeError(
                    f"QueryBuilder.join() was not called for these SQL tables: {repr(missing_tables)}"
                )


class QueryBuilder:
    def __init__(self):
        self._table: Optional[Table] = None
        self._residual_policy: Optional[ResidualPolicyResponse] = None
        self._refs: Optional[Dict[str, Column]] = None
        self._joins: List[Tuple[Table, Condition]] = []

    def select(self, table: Table) -> "QueryBuilder":
        self._table = table
        return self

    def filter_by(self, residual_policy: ResidualPolicyResponse) -> "QueryBuilder":
        self._residual_policy = residual_policy
        return self

    def map_references(self, refs: Dict[str, Column]) -> "QueryBuilder":
        self._refs = refs
        return self

    def join(self, table: Table, condition: Condition) -> "QueryBuilder":
        self._joins.append((table, condition))
        return self

    def _verify_args(self):
        if self._table is None:
            raise ValueError(
                f"You must call QueryBuilder.select(table) to specify to main table to filter on"
            )

        if self._residual_policy is None:
            raise ValueError(
                f"You must call QueryBuilder.filter_by(residual_policy) to specify the compiled partial policy returned from OPA"
            )

        if self._refs is None:
            raise ValueError(
                f"You must call QueryBuilder.map_references(refs) to specify how to map residual OPA references to SQL tables"
            )

    def build(self) -> Select:
        self._verify_args()

        table = self._table
        residual_policy = self._residual_policy
        refs = self._refs
        join_conditions = self._joins

        select_all = cast(Select, sa.select(table))

        if residual_policy.type == ResidualPolicyType.ALWAYS_ALLOW:
            return select_all

        if residual_policy.type == ResidualPolicyType.ALWAYS_DENY:
            return select_all.where(False)

        verify_join_conditions(table, refs, join_conditions)

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
                column = refs[variable_ref]
            except KeyError:
                raise KeyError(
                    f"Residual variable does not exist in the reference mapping: {variable_ref}"
                )

            # the operator handlers here are the leaf nodes of the recursion
            return operator_to_sql(operator, column, value)

        query: Select = select_all.where(to_sql(residual_policy.condition))

        if join_conditions:
            query = query.select_from(table)
            for join_table, predicate in join_conditions:
                query = query.join(join_table, predicate)

        return query


def to_query(
    filters: ResidualPolicyResponse,
    table: Table,
    *,
    refs: Dict[str, Column],
    join_conditions: Optional[List[Tuple[Table, Condition]]] = None,
) -> Select:
    query_builder = QueryBuilder().select(table).filter_by(filters).map_references(refs)
    if join_conditions is not None:
        for joined_table, join_condition in join_conditions:
            query_builder = query_builder.join(joined_table, join_condition)
    return query_builder.build()
