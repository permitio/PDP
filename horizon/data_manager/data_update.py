from typing import Any, Iterator, Self

from pydantic import BaseModel


class Fact(BaseModel):
    type: str
    attributes: dict[str, str]


class InsertOperation(BaseModel):
    fact: Fact


class DeleteOperation(BaseModel):
    fact: Fact


AnyOperation = InsertOperation | DeleteOperation


class DataUpdate(BaseModel):
    inserts: list[InsertOperation]
    deletes: list[DeleteOperation]

    @classmethod
    def from_operations(cls, operations: Iterator[AnyOperation]) -> Self:
        inserts, deletes = [], []
        for operation in operations:
            if isinstance(operation, InsertOperation):
                inserts.append(operation)
            elif isinstance(operation, DeleteOperation):
                deletes.append(operation)

        return cls(
            inserts=inserts,
            deletes=deletes,
        )
