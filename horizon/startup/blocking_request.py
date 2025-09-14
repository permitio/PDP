from typing import Any

import requests

from horizon.startup.exceptions import InvalidPDPTokenError


class BlockingRequest:
    def __init__(self, token: str | None, extra_headers: dict[str, Any] | None = None, timeout: float = 60):
        self._token = token
        self._extra_headers = {k: v for k, v in (extra_headers or {}).items() if v is not None}
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {}
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"

        headers.update(self._extra_headers)
        return headers

    def get(self, url: str, params=None) -> dict:
        """
        utility method to send a *blocking* HTTP GET request and get the response back.
        """
        response = requests.get(url, headers=self._headers(), params=params, timeout=self._timeout)

        if response.status_code == 401:
            raise InvalidPDPTokenError()

        return response.json()

    def post(self, url: str, payload: dict | None = None, params=None) -> dict:
        """
        utility method to send a *blocking* HTTP POST request with a JSON payload and get the response back.
        """
        response = requests.post(url, json=payload, headers=self._headers(), params=params, timeout=self._timeout)

        if response.status_code == 401:
            raise InvalidPDPTokenError()

        return response.json()
