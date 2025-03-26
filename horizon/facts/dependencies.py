from typing import Annotated

from fastapi import Depends, HTTPException, Request
from loguru import logger
from opal_client import OpalClient

from horizon.config import sidecar_config
from horizon.facts.timeout_policy import TimeoutPolicy
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


DataUpdateSubscriberDependency = Annotated[DataUpdateSubscriber, Depends(get_data_update_subscriber)]


def get_wait_timeout(request: Request) -> float | None:
    wait_timeout = request.headers.get("X-Wait-timeout", sidecar_config.LOCAL_FACTS_WAIT_TIMEOUT)
    if not wait_timeout:
        return None
    try:
        wait_timeout = float(wait_timeout)
    except ValueError as e:
        logger.error(f"Invalid X-Wait-timeout header, expected float, got {wait_timeout!r}")
        raise HTTPException(
            status_code=400,
            detail=f"Invalid X-Wait-timeout header, expected float, got {wait_timeout!r}",
        ) from e
    if wait_timeout < 0:
        return None
    else:
        return wait_timeout


WaitTimeoutDependency = Annotated[float | None, Depends(get_wait_timeout)]


def get_timeout_policy(request: Request) -> TimeoutPolicy:
    policy_str = request.headers.get("X-Timeout-Policy", TimeoutPolicy.IGNORE.value)
    try:
        return TimeoutPolicy(policy_str.lower())
    except ValueError as e:
        logger.error(f"Invalid X-Timeout-Policy header, expected one of {list(TimeoutPolicy)}, got {policy_str!r}")
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid X-Timeout-Policy header, expected one of {[p.value for p in TimeoutPolicy]}, "
                f"got {policy_str!r}"
            ),
        ) from e


TimeoutPolicyDependency = Annotated[TimeoutPolicy, Depends(get_timeout_policy)]
