from typing import Annotated

from fastapi import Depends, Request
from fastapi_websocket_pubsub import PubSubClient
from opal_client import OpalClient


def get_opal_client(request: Request) -> OpalClient:
    return request.app.state.opal_client


OpalClientDependency = Annotated[OpalClient, Depends(get_opal_client)]


def get_opal_ws_client(opal_client: OpalClientDependency) -> PubSubClient:
    return opal_client.data_updater._client


OpalWsClientDependency = Annotated[PubSubClient, Depends(get_opal_ws_client)]
