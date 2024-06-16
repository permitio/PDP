from typing import Annotated

from fastapi import Depends, Request
from opal_client import OpalClient

from facts.update_subscriber import DataUpdateSubscriber


def get_opal_client(request: Request) -> OpalClient:
    return request.app.state.opal_client


OpalClientDependency = Annotated[OpalClient, Depends(get_opal_client)]

_data_update_subscriber: DataUpdateSubscriber | None = None


def get_data_update_subscriber(
    opal_client: OpalClientDependency,
) -> DataUpdateSubscriber:
    global _data_update_subscriber
    if _data_update_subscriber is None:
        _data_update_subscriber = DataUpdateSubscriber(opal_client.data_updater)

    return _data_update_subscriber


DataUpdateSubscriberDependency = Annotated[
    DataUpdateSubscriber, Depends(get_data_update_subscriber)
]
