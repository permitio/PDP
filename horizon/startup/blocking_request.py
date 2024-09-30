from typing import Optional, Any, Dict

from loguru import logger

import requests

from horizon.ssl import get_mtls_requests_kwargs
from horizon.startup.exceptions import InvalidPDPTokenException


class BlockingRequest:
    def __init__(
        self, token: Optional[str], extra_headers: dict[str, Any] | None = None
    ):
        self._token = token
        self._extra_headers = {
            k: v for k, v in (extra_headers or {}).items() if v is not None
        }
        self._mtls_kwargs = get_mtls_requests_kwargs()

    def _headers(self) -> Dict[str, str]:
        headers = {}
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"

        headers.update(self._extra_headers)
        return headers

    def _process_response(self, response: requests.Response) -> dict:
        content_type = response.headers.get("Content-Type", "")

        # if the response is not json, log the issue so we know what went wrong
        if "application/json" not in content_type:
            error_text = f"Non-JSON response: {response.text}"
            logger.error(error_text)
            raise ValueError(error_text)

        if response.status_code == 401:
            raise InvalidPDPTokenException()

        try:
            return response.json()
        except ValueError:
            logger.error(f"Failed to parse JSON response: {response.text}")
            raise ValueError("unable to parse json")

    def get(self, url: str, params=None) -> dict:
        """
        utility method to send a *blocking* HTTP GET request and get the response back.
        """
        response = requests.get(
            url, headers=self._headers(), params=params, **self._mtls_kwargs
        )
        return self._process_response(response)

    def post(self, url: str, payload: dict = None, params=None) -> dict:
        """
        utility method to send a *blocking* HTTP POST request with a JSON payload and get the response back.
        """
        response = requests.post(
            url,
            json=payload,
            headers=self._headers(),
            params=params,
            **self._mtls_kwargs,
        )
        return self._process_response(response)
