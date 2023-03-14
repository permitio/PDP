from pydantic import BaseModel


class VersionResult(BaseModel):
    api_version: int
