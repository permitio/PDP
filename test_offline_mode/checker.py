import asyncio
import logging.config
import os

import aiohttp
from permit import Permit, PermitConfig

logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "color": {
                "()": "colorlog.ColoredFormatter",
                "format": "%(log_color)s[%(asctime)s.%(msecs)03d] %(levelname)s - " "%(name)s:%(lineno)d | %(message)s",
                "datefmt": "%H:%M:%S",
                "log_colors": {
                    "DEBUG": "white",
                    "INFO": "green",
                    "WARNING": "yellow",
                    "ERROR": "red",
                    "CRITICAL": "red,bg_white",
                },
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "color",
            },
        },
        "root": {
            "handlers": ["console"],
            "level": "INFO",
        },
    }
)
logger = logging.getLogger(__name__)


async def main():
    pdp_url = os.environ["PDP_URL"]
    logger.info("Starting PDP checker against: %s", pdp_url)
    permit = Permit(
        PermitConfig(
            token=os.environ["PDP_API_KEY"],
            api_url=os.environ["PDP_CONTROL_PLANE"],
            pdp=pdp_url,
        )
    )

    while True:
        try:
            result = await permit.check("user-1", "create", "file")
            if result:
                logger.info("Passed")
            else:
                logger.warning("Failed")
        except Exception as e:
            logger.exception(f"Error: {e}")

        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
