# from typing import Union

# from horizon.enforcer import schemas as enforcer_schemas
# from horizon.enforcer.api import MAIN_PARTIAL_EVAL_PACKAGE
# from permit_datafilter.boolean_expression.schemas import (
#     ResidualPolicyResponse,
# )
# from permit_datafilter.compile_api.compile_client import OpaCompileClient

# User = Union[dict, str]
# Action = str
# Resource = Union[dict, str]


# def normalize_user(user: User) -> dict:
#     if isinstance(user, str):
#         return dict(key=user)
#     else:
#         return user


# def normalize_resource_type(resource: Resource) -> str:
#     if isinstance(resource, dict):
#         t = resource.get("type", None)
#         if t is not None and isinstance(t, str):
#             return t
#         raise ValueError("no resource type provided")
#     else:
#         return resource


# def filter_resource_query(
#     user: User, action: Action, resource: Resource
# ) -> enforcer_schemas.AuthorizationQuery:
#     normalized_user = normalize_user(user)
#     resource_type: str = normalize_resource_type(resource)
#     return enforcer_schemas.AuthorizationQuery(
#         user=normalized_user,
#         action=action,
#         resource=enforcer_schemas.Resource(type=resource_type),
#     )


# class Permit:
#     """
#     stub for future SDK code
#     """

#     def __init__(self, token: str):
#         self._headers = {
#             "Authorization": f"Bearer {token}",
#             "Content-Type": "application/json",
#         }

#     async def filter_resources(
#         self, user: User, action: Action, resource: Resource
#     ) -> ResidualPolicyResponse:
#         """
#         stub for future permit.filter_resources() function
#         """
#         client = OpaCompileClient(headers=self._headers)
#         input = filter_resource_query(user, action, resource)
#         return await client.compile_query(
#             query=f"data.{MAIN_PARTIAL_EVAL_PACKAGE}.allow == true",
#             input=input,
#             unknowns=[
#                 "input.resource.key",
#                 "input.resource.tenant",
#                 "input.resource.attributes",
#             ],
#             raw=True,
#         )
