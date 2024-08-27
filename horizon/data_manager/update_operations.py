import json
from typing import Iterator
from uuid import uuid4

from opal_common.schemas.data import JsonableValue

from horizon.data_manager.data_update import AnyOperation, InsertOperation, Fact


def _get_operations_for_update_relationship_tuple(
    obj: str, data: JsonableValue
) -> Iterator[AnyOperation]:
    for full_relation, targets in data.items():
        relation = full_relation.lstrip("relation:")
        for target_type, target_objects in targets.items():
            for target in target_objects:
                yield InsertOperation(
                    fact=Fact(
                        type="relationship_tuples",
                        attributes={
                            "id": str(uuid4()),
                            "subject": f"{target_type}:{target}",
                            "relation": relation,
                            "object": obj,
                        },
                    )
                )


def _get_operations_for_update_role_assigment(
    full_user_key: str, data: JsonableValue
) -> Iterator[AnyOperation]:
    user_key = full_user_key.lstrip("user:")
    for subject, roles in data.items():
        subject_type, subject_key = subject.split(":", 1)
        for role_key in roles:
            if subject_type == "__tenant":
                yield InsertOperation(
                    fact=Fact(
                        type="role_assignments",
                        attributes={
                            "id": str(uuid4()),
                            "actor": user_key,
                            "tenant": subject_key,
                            "role": role_key,
                            "resource": "",
                        },
                    )
                )
            else:
                yield InsertOperation(
                    fact=Fact(
                        type="role_assignments",
                        attributes={
                            "id": str(uuid4()),
                            "actor": user_key,
                            "tenant": "",
                            "role": role_key,
                            "resource": subject,
                        },
                    )
                )


def _get_operations_for_update_user(
    user_key: str, data: JsonableValue
) -> Iterator[AnyOperation]:
    attributes = data.get("attributes", {})
    yield InsertOperation(
        fact=Fact(
            type="users",
            attributes={
                "id": user_key,
                "attributes": json.dumps(attributes),
                # TODO remove the json.dumps after fixing the map[string]string issue in Go
            },
        )
    )


def _get_operations_for_update_resource_instance(
    instance_key: str, data: JsonableValue
) -> Iterator[AnyOperation]:
    attributes = data.get("attributes", {})
    yield InsertOperation(
        fact=Fact(
            type="resource_instance",
            attributes={
                "id": instance_key,
                "attributes": json.dumps(attributes),
                # TODO remove the json.dumps after fixing the map[string]string issue in Go
            },
        )
    )
