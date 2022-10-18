from fastapi import APIRouter, Depends, status

from horizon.authentication import enforce_pdp_token
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

    return router
