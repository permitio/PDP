from pydantic import BaseModel


class RemoteConfig(BaseModel):
    opal_common: dict = {}
    opal_client: dict = {}
    pdp: dict = {}
    context: dict = {}
