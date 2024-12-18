from horizon.pdp import *

try:
    # expose app for Uvicorn
    sidecar = PermitPDP()
    app = sidecar.app
except SystemExit:
    raise
except Exception:
    logger.opt(exception=True).critical("Sidecar failed to start because of exception: {err}")
    raise SystemExit(1)
