import pytest

from horizon.enforcer.data_filtering.sdk.permit_filter import Permit

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.orm import declarative_base, relationship

from horizon.enforcer.data_filtering.sdk.permit_sqlalchemy import to_query

Base = declarative_base()


# example db model
class User(Base):
    __tablename__ = "user"

    id = Column(String, primary_key=True)
    username = Column(String(255))
    email = Column(String(255))


class Tenant(Base):
    __tablename__ = "tenant"

    id = Column(String, primary_key=True)
    name = Column(String(255))


class Task(Base):
    __tablename__ = "task"

    id = Column(String, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow())
    updated_at = Column(DateTime)
    description = Column(String(255))
    tenant_id = Column(String(255))
    tenant_id_joined = Column(String, ForeignKey("tenant.id"))
    tenant = relationship("Tenant", back_populates="tasks")


async def test_data_filtering_e2e():
    """
    tests how df should work e2e with stub sdk
    """
    permit = Permit(token="<secret>")
    filter = await permit.filter_resources("user", "read", "task")

    sa_query = to_query(
        filter,
        Task,
        refs={
            # example how to map a column on the same model
            "input.resource.tenant": Task.tenant_id,
        },
    )

    sa_query = to_query(
        filter,
        Task,
        refs={
            # example how to map a column on a related model
            "input.resource.tenant_id": Tenant.id,
        },
        join_conditions=[(Tenant, Task.tenant_id_joined == Tenant.id)],
    )
