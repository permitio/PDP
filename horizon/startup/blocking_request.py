from typing import Optional, Any, Dict

import requests

from horizon.startup.exceptions import InvalidPDPTokenException
from opal_common.security.sslcontext import (
    get_custom_ssl_context_for_mtls,
    CustomSSLContext,
)


class BlockingRequest:
    def __init__(
        self, token: Optional[str], extra_headers: dict[str, Any] | None = None
    ):
        self._token = token
        self._extra_headers = {
            k: v for k, v in (extra_headers or {}).items() if v is not None
        }
        custom_ssl_context: Optional[CustomSSLContext] = (
            get_custom_ssl_context_for_mtls()
        )
        self._ssl_kwargs = {}
        if custom_ssl_context is not None:
            self._ssl_kwargs["cert"] = (
                custom_ssl_context.certfile,
                custom_ssl_context.keyfile,
            )
            if custom_ssl_context.cafile is not None:
                self._ssl_kwargs["verify"] = custom_ssl_context.cafile

    def _headers(self) -> Dict[str, str]:
        headers = {}
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"

        headers.update(self._extra_headers)
        return headers

    def get(self, url: str, params=None) -> dict:
        """
        utility method to send a *blocking* HTTP GET request and get the response back.
        """
        response = requests.get(
            url, headers=self._headers(), params=params, **self._ssl_kwargs
        )

        if response.status_code == 401:
            raise InvalidPDPTokenException()

        return response.json()

    def post(self, url: str, payload: dict = None, params=None) -> dict:
        """
        utility method to send a *blocking* HTTP POST request with a JSON payload and get the response back.
        """
        response = requests.post(
            url,
            json=payload,
            headers=self._headers(),
            params=params,
            **self._ssl_kwargs,
        )

        if response.status_code == 401:
            raise InvalidPDPTokenException()

        return response.json()
