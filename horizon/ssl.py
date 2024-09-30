from typing import Optional

from loguru import logger
from opal_common.config import opal_common_config
from opal_common.security.sslcontext import (
    CustomSSLContext,
    get_custom_ssl_context_for_mtls,
)


def get_mtls_context() -> Optional[CustomSSLContext]:
    custom_ssl_context: Optional[CustomSSLContext] = None

    if (
        opal_common_config.MTLS_CLIENT_CERT is not None
        and opal_common_config.MTLS_CLIENT_KEY is not None
    ):
        custom_ssl_context = get_custom_ssl_context_for_mtls(
            client_cert_file=opal_common_config.MTLS_CLIENT_CERT,
            client_key_file=opal_common_config.MTLS_CLIENT_KEY,
            ca_file=opal_common_config.MTLS_CA_CERT,
        )

        if custom_ssl_context is not None:
            logger.info(
                "Using client mTLS SSL context, client_cert_file={}, client_key_file={}, ca_file={}",
                custom_ssl_context.certfile,
                custom_ssl_context.keyfile,
                custom_ssl_context.cafile,
            )
            return custom_ssl_context

    return None


def get_mtls_requests_kwargs() -> dict:
    custom_ssl_context: Optional[CustomSSLContext] = get_mtls_context()

    if custom_ssl_context is not None:
        return dict(
            cert=(
                custom_ssl_context.certfile,
                custom_ssl_context.keyfile,
            ),
            verify=(
                custom_ssl_context.cafile
                if custom_ssl_context.cafile is not None
                else True
            ),
        )

    return dict()


def get_mtls_aiohttp_kwargs() -> dict:
    custom_ssl_context: Optional[CustomSSLContext] = get_mtls_context()

    return (
        dict(ssl=custom_ssl_context.ssl_context)
        if custom_ssl_context is not None
        else dict()
    )


def get_mtls_httpx_kwargs() -> dict:
    # same params as in requests library
    return get_mtls_requests_kwargs()
