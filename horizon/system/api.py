import asyncio
import sys

from fastapi import APIRouter, Depends, Query, status

from horizon.authentication import enforce_pdp_control_key, enforce_pdp_token
from horizon.system.consts import API_VERSION
from horizon.system.schemas import VersionResult


def init_system_api_router():
    router = APIRouter()

    @router.get(
        "/version",
        response_model=VersionResult,
        status_code=status.HTTP_200_OK,
        dependencies=[Depends(enforce_pdp_token)],
    )
    async def version() -> VersionResult:
        result = VersionResult(api_version=API_VERSION)
        return result

    @router.post(
        "/_exit",
        status_code=status.HTTP_204_NO_CONTENT,
        dependencies=[Depends(enforce_pdp_control_key)],
    )
    async def exit(exit_code: int = Query(default=0, ge=0, le=255)):
        async def do_exit():
            await asyncio.sleep(0.1)
            sys.exit(exit_code)

        asyncio.ensure_future(do_exit())

    return router
