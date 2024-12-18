import asyncio
import os

from fastapi import APIRouter, Depends, status
from loguru import logger

from horizon.authentication import enforce_pdp_control_key, enforce_pdp_token
from horizon.system.consts import API_VERSION, GUNICORN_EXIT_APP
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
    async def exit():
        async def do_exit():
            await asyncio.sleep(0.1)
            logger.info("Exiting due to system request.")
            os._exit(GUNICORN_EXIT_APP)

        asyncio.ensure_future(do_exit())

    return router
