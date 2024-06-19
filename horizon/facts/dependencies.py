from typing import Annotated

from fastapi import Depends, Request, HTTPException
from opal_client import OpalClient

from horizon.config import sidecar_config
from horizon.facts.update_subscriber import DataUpdateSubscriber


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


def get_wait_timeout(request: Request) -> float | None:
    wait_timeout = request.headers.get(
        "X-Wait-timeout", sidecar_config.LOCAL_FACTS_WAIT_TIMEOUT
    )
    try:
        wait_timeout = float(wait_timeout)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid X-Wait-timeout header, expected float, got {wait_timeout!r}",
        ) from e
    if wait_timeout < 0:
        return None
    else:
        return wait_timeout


WaitTimeoutDependency = Annotated[float | None, Depends(get_wait_timeout)]
