import pytest

from permit_datafilter.boolean_expression.schemas import (
    ResidualPolicyResponse,
)

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import Select
from sqlalchemy.orm import declarative_base, relationship

from permit_datafilter.plugins.sqlalchemy import to_query

Base = declarative_base()


def query_to_string(query: Select) -> str:
    """
    utility function to print raw sql statement
    """
    return str(
        query.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


def striplines(s: str) -> str:
    return "\n".join([line.strip() for line in s.splitlines()])


def test_sql_translation_no_join():
    """
    tests residual policy to sql conversion without joins
    """
    # this would be an e2e test, but harder to run with pytest
    # since the api key is always changing
    # ---
    # token = os.environ.get("PDP_API_KEY", "<secret>")
    # permit = Permit(token=token)
    # filter = await permit.filter_resources("user", "read", "task")

    # another option is to mock the residual policy
    filter = ResidualPolicyResponse(
        **{
            "type": "conditional",
            "condition": {
                "expression": {
                    "operator": "eq",
                    "operands": [
                        {"variable": "input.resource.tenant"},
                        {"value": "082f6978-6424-4e05-a706-1ab6f26c3768"},
                    ],
                }
            },
        }
    )

    class Task(Base):
        __tablename__ = "task"

        id = Column(String, primary_key=True)
        created_at = Column(DateTime, default=datetime.utcnow())
        updated_at = Column(DateTime)
        description = Column(String(255))
        tenant_id = Column(String(255))

    sa_query = to_query(
        filter,
        Task,
        refs={
            # example how to map a column on the same model
            "input.resource.tenant": Task.tenant_id,
        },
    )

    str_query = query_to_string(sa_query)

    assert striplines(str_query) == striplines(
        """SELECT task.id, task.created_at, task.updated_at, task.description, task.tenant_id
        FROM task
        WHERE task.tenant_id = '082f6978-6424-4e05-a706-1ab6f26c3768'"""
    )

    str_query_only_columns = query_to_string(sa_query.with_only_columns(Task.id))

    assert striplines(str_query_only_columns) == striplines(
        """SELECT task.id
        FROM task
        WHERE task.tenant_id = '082f6978-6424-4e05-a706-1ab6f26c3768'"""
    )


def test_sql_translation_with_join():
    """
    tests residual policy to sql conversion without joins
    """
    filter = ResidualPolicyResponse(
        **{
            "type": "conditional",
            "condition": {
                "expression": {
                    "operator": "eq",
                    "operands": [
                        {"variable": "input.resource.tenant"},
                        {"value": "082f6978-6424-4e05-a706-1ab6f26c3768"},
                    ],
                }
            },
        }
    )

    class Tenant(Base):
        __tablename__ = "tenant"

        id = Column(String, primary_key=True)
        key = Column(String(255))

    class TaskJoined(Base):
        __tablename__ = "task_joined"

        id = Column(String, primary_key=True)
        created_at = Column(DateTime, default=datetime.utcnow())
        updated_at = Column(DateTime)
        description = Column(String(255))
        tenant_id_joined = Column(String, ForeignKey("tenant.id"))
        tenant = relationship("Tenant", backref="tasks")

    sa_query = to_query(
        filter,
        TaskJoined,
        refs={
            # example how to map a column on a related model
            "input.resource.tenant": Tenant.key,
        },
        join_conditions=[(Tenant, TaskJoined.tenant_id_joined == Tenant.id)],
    )

    str_query = query_to_string(sa_query)

    assert striplines(str_query) == striplines(
        """SELECT task_joined.id, task_joined.created_at, task_joined.updated_at, task_joined.description, task_joined.tenant_id_joined
        FROM task_joined JOIN tenant ON task_joined.tenant_id_joined = tenant.id
        WHERE tenant.key = '082f6978-6424-4e05-a706-1ab6f26c3768'"""
    )


def test_sql_translation_of_trivial_policies():
    class Tasks(Base):
        __tablename__ = "tasks"

        id = Column(String, primary_key=True)
        created_at = Column(DateTime, default=datetime.utcnow())
        updated_at = Column(DateTime)
        description = Column(String(255))
        tenant_id = Column(String(255))

    filter = ResidualPolicyResponse(**{"type": "always_allow", "condition": None})

    sa_query = to_query(
        filter,
        Tasks,
        refs={
            # example how to map a column on the same model
            "input.resource.tenant": Tasks.tenant_id,
        },
    )

    str_query = query_to_string(sa_query)
    assert striplines(str_query) == striplines(
        """SELECT tasks.id, tasks.created_at, tasks.updated_at, tasks.description, tasks.tenant_id
        FROM tasks"""
    )  # this query would always return all rows from the tasks table

    filter = ResidualPolicyResponse(**{"type": "always_deny", "condition": None})

    sa_query = to_query(
        filter,
        Tasks,
        refs={
            # example how to map a column on the same model
            "input.resource.tenant": Tasks.tenant_id,
        },
    )

    str_query = query_to_string(sa_query)
    assert striplines(str_query) == striplines(
        """SELECT tasks.id, tasks.created_at, tasks.updated_at, tasks.description, tasks.tenant_id
        FROM tasks
        WHERE false"""
    )  # this query would never have any results


def test_missing_joins():
    filter = ResidualPolicyResponse(
        **{
            "type": "conditional",
            "condition": {
                "expression": {
                    "operator": "eq",
                    "operands": [
                        {"variable": "input.resource.tenant"},
                        {"value": "082f6978-6424-4e05-a706-1ab6f26c3768"},
                    ],
                }
            },
        }
    )

    class User2(Base):
        __tablename__ = "user2"

        id = Column(String, primary_key=True)
        username = Column(String(255))

    class Tenant2(Base):
        __tablename__ = "tenant2"

        id = Column(String, primary_key=True)
        key = Column(String(255))

    class TaskJoined2(Base):
        __tablename__ = "task_joined2"

        id = Column(String, primary_key=True)
        created_at = Column(DateTime, default=datetime.utcnow())
        updated_at = Column(DateTime)
        description = Column(String(255))
        tenant_id_joined = Column(String, ForeignKey("tenant2.id"))
        tenant = relationship("Tenant2", backref="tasks")
        owner_id = Column(String, ForeignKey("user2.id"))
        owner = relationship("User2", backref="tasks")

    with pytest.raises(TypeError) as e:
        # Tenant2.key is a column outside the main table (requires a join)
        # if we don't provide any join conditions, to_query() will throw a TypeError
        sa_query = to_query(
            filter,
            TaskJoined2,
            refs={
                # example how to map a column on a related model
                "input.resource.tenant": Tenant2.key,
            },
        )

    assert (
        str(e.value)
        == "You must call QueryBuilder.join(table, condition) to map residual references to other SQL tables"
    )

    with pytest.raises(TypeError) as e:
        # Tenant2.key is a column outside the main table (requires a join)
        # if we provide join conditions but not to all required tables,
        # to_query() will throw a different TypeError
        sa_query = to_query(
            filter,
            TaskJoined2,
            refs={
                # example how to map a column on a related model
                "input.resource.tenant": Tenant2.key,
            },
            join_conditions=[(User2, TaskJoined2.owner_id == User2.id)],
        )

    assert (
        str(e.value)
        == "QueryBuilder.join() was not called for these SQL tables: {'tenant2'}"
    )
