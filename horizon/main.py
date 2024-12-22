from loguru import logger

from horizon.pdp import PermitPDP

try:
    # expose app for Uvicorn
    sidecar = PermitPDP()
    app = sidecar.app
except SystemExit as e:
    raise e
except Exception as e:
    logger.opt(exception=True).critical("Sidecar failed to start because of exception: {err}")
    raise SystemExit(1) from e
