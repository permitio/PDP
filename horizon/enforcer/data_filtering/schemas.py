from __future__ import annotations

from typing import Any, List, Optional, Union

from pydantic import BaseModel, Field


class BaseSchema(BaseModel):
    class Config:
        orm_mode = True
        allow_population_by_field_name = True


class CompileResponse(BaseSchema):
    result: "CompileResponseComponents"


class CompileResponseComponents(BaseSchema):
    queries: Optional["CRQuerySet"] = None
    support: Optional["CRSupportBlock"] = None


class CRQuerySet(BaseSchema):
    __root__: List["CRQuery"]


class CRQuery(BaseSchema):
    __root__: List["CRExpression"]


class CRExpression(BaseSchema):
    index: int
    terms: Union["CRTerm", List["CRTerm"]]


class CRTerm(BaseSchema):
    type: str
    value: Any


class CRSupportBlock(BaseSchema):
    __root__: List["CRSupportModule"]


class CRSupportModule(BaseSchema):
    package: "CRSupportModulePackage"
    rules: List["CRRegoRule"]


class CRSupportModulePackage(BaseSchema):
    path: List["CRTerm"]


class CRRegoRule(BaseSchema):
    body: List["CRExpression"]
    head: "CRRuleHead"


class CRRuleHead(BaseSchema):
    name: str
    key: "CRTerm"
    ref: List["CRTerm"]


CompileResponse.update_forward_refs()
CompileResponseComponents.update_forward_refs()
CRQuerySet.update_forward_refs()
CRQuery.update_forward_refs()
CRExpression.update_forward_refs()
CRTerm.update_forward_refs()
CRSupportBlock.update_forward_refs()
CRSupportModule.update_forward_refs()
CRSupportModulePackage.update_forward_refs()
CRRegoRule.update_forward_refs()
CRRuleHead.update_forward_refs()
