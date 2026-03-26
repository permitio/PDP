from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from horizon.authentication import enforce_pdp_token

if TYPE_CHECKING:
    from opal_client.client import OpalClient


class ConnectivityStatus(BaseModel):
    control_plane_connectivity_disabled: bool
    offline_mode_enabled: bool


class ConnectivityActionResult(BaseModel):
    status: str


def init_connectivity_router(opal_client: OpalClient):
    router = APIRouter(
        prefix="/control-plane",
        dependencies=[Depends(enforce_pdp_token)],
    )

    @router.get(
        "/connectivity",
        status_code=status.HTTP_200_OK,
        response_model=ConnectivityStatus,
        summary="Get control plane connectivity status",
        description="Returns the current connectivity state to the control plane and whether offline mode is enabled.",
    )
    async def get_connectivity_status():
        return ConnectivityStatus(
            control_plane_connectivity_disabled=opal_client.opal_server_connectivity_disabled,
            offline_mode_enabled=opal_client.offline_mode_enabled,
        )

    @router.post(
        "/connectivity/enable",
        status_code=status.HTTP_200_OK,
        response_model=ConnectivityActionResult,
        summary="Enable control plane connectivity",
        description="Starts the policy and data updaters, reconnecting to the control plane. "
        "Triggers a full rehydration (policy refetch + data refetch). "
        "Requires offline mode to be enabled.",
    )
    async def enable_connectivity():
        if not opal_client.offline_mode_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot enable control plane connectivity: offline mode is not enabled",
            )
        if not opal_client.opal_server_connectivity_disabled:
            return ConnectivityActionResult(status="already_enabled")

        await opal_client.enable_opal_server_connectivity()
        return ConnectivityActionResult(status="enabled")

    @router.post(
        "/connectivity/disable",
        status_code=status.HTTP_200_OK,
        response_model=ConnectivityActionResult,
        summary="Disable control plane connectivity",
        description="Stops the policy and data updaters, disconnecting from the control plane. "
        "Requires offline mode to be enabled. The policy store continues serving from its current state.",
    )
    async def disable_connectivity():
        if not opal_client.offline_mode_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot disable control plane connectivity: offline mode is not enabled",
            )
        if opal_client.opal_server_connectivity_disabled:
            return ConnectivityActionResult(status="already_disabled")

        await opal_client.disable_opal_server_connectivity()
        return ConnectivityActionResult(status="disabled")

    return router
