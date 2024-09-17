import json
from typing import Iterator

from opal_common.schemas.data import JsonableValue

from horizon.data_manager.data_update import (
    AnyOperation,
    InsertOperation,
    Fact,
    DeleteOperation,
)


def _get_operations_for_update_relationship_tuple(
    obj: str, data: JsonableValue
) -> Iterator[AnyOperation]:
    yield DeleteOperation(
        fact=Fact(
            type="relationship_tuples",
            attributes={"object": obj},
        ),
    )
    for full_relation, targets in data.items():
        relation = full_relation.lstrip("relation:")
        for target_type, target_objects in targets.items():
            for target in target_objects:
                yield InsertOperation(
                    fact=Fact(
                        type="relationship_tuples",
                        attributes={
                            "subject": f"{target_type}:{target}",
                            "relation": relation,
                            "object": obj,
                        },
                    ),
                )


def _get_operations_for_update_role_assigment(
    full_user_key: str, data: JsonableValue
) -> Iterator[AnyOperation]:
    user_key = full_user_key.lstrip("user:")
    yield DeleteOperation(
        fact=Fact(
            type="role_assignments",
            attributes={"actor": user_key},
        ),
    )
    for subject, roles in data.items():
        subject_type, subject_key = subject.split(":", 1)
        for role_key in roles:
            if subject_type == "__tenant":
                yield InsertOperation(
                    fact=Fact(
                        type="role_assignments",
                        attributes={
                            "actor": f"user:{user_key}",
                            "tenant": subject_key,
                            "role": role_key,
                            "resource": subject,
                        },
                    ),
                )
            else:
                yield InsertOperation(
                    fact=Fact(
                        type="role_assignments",
                        attributes={
                            "actor": f"user:{user_key}",
                            "tenant": "",
                            "role": role_key,
                            "resource": subject,
                        },
                    ),
                )


def _get_operations_for_update_user(
    user_key: str, data: JsonableValue
) -> Iterator[AnyOperation]:
    attributes = data.get("attributes", {})
    if attributes:
        yield InsertOperation(
            fact=Fact(
                type="users",
                attributes={
                    "id": f"user:{user_key}",
                    "attributes": json.dumps(attributes),
                    # TODO remove the json.dumps after fixing the map[string]string issue in Go
                },
            ),
        )
    else:
        # When an object is deleted, a data update with an empty attributes object is sent
        # We cascade the deletion to all related facts
        yield DeleteOperation(
            fact=Fact(
                type="users",
                attributes={"id": f"user:{user_key}"},
            ),
        )
        yield DeleteOperation(
            fact=Fact(
                type="role_assignments",
                attributes={"actor": f"user:{user_key}"},
            ),
        )


def _get_operations_for_update_resource_instance(
    instance_key: str, data: JsonableValue
) -> Iterator[AnyOperation]:
    attributes = data.get("attributes", {})
    if attributes:
        yield InsertOperation(
            fact=Fact(
                type="instances",
                attributes={
                    "id": instance_key,
                    "attributes": json.dumps(attributes),
                    # TODO remove the json.dumps after fixing the map[string]string issue in Go
                },
            ),
        )
    else:
        # When an object is deleted, a data update with an empty attributes object is sent
        # We cascade the deletion to all related facts
        yield DeleteOperation(
            fact=Fact(
                type="instances",
                attributes={"id": instance_key},
            ),
        )
        yield DeleteOperation(
            fact=Fact(
                type="relationship_tuples",
                attributes={"object": instance_key},
            ),
        )
        yield DeleteOperation(
            fact=Fact(
                type="relationship_tuples",
                attributes={"subject": instance_key},
            ),
        )
        yield DeleteOperation(
            fact=Fact(
                type="role_assignments",
                attributes={"resource": instance_key},
            ),
        )
