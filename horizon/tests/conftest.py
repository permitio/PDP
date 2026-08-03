"""Pytest configuration and compatibility shims for the horizon test-suite.

aioresponses (our HTTP mocking library) builds ``aiohttp.ClientResponse``
instances directly. aiohttp 3.14 made ``stream_writer`` a *required*
keyword-only argument of ``ClientResponse.__init__`` (it is only read for its
``output_size``), which the latest released aioresponses (0.7.9) does not pass,
so every mocked response raises::

    TypeError: ClientResponse.__init__() missing 1 required keyword-only
    argument: 'stream_writer'

We intentionally stay on the aiohttp 3.14.x line: the June 2026 security fixes
(e.g. GHSA-63hw-fmq6-xxg2 and the other advisories in that batch) landed in
3.14 and were not backported to 3.13.x, so pinning aiohttp down just to satisfy
aioresponses would reintroduce those CVEs into the shipped image. Instead we
mirror the upstream aioresponses fix (PR #288, not yet released) by injecting a
dummy ``stream_writer``. This is a no-op on aiohttp < 3.14 and can be removed
once aioresponses publishes a release that includes PR #288.
"""

import inspect
from unittest.mock import Mock

import aioresponses.core as _aioresponses_core
from aiohttp.client_reqrep import ClientResponse as _ClientResponse

if "stream_writer" in inspect.signature(_ClientResponse.__init__).parameters:

    class _StreamWriterCompatClientResponse(_ClientResponse):
        """ClientResponse that supplies aiohttp 3.14's required stream_writer."""

        def __init__(self, *args, **kwargs):
            if "stream_writer" not in kwargs:
                kwargs["stream_writer"] = Mock(output_size=0)
            super().__init__(*args, **kwargs)

    # aioresponses._build_response falls back to this module-level name when the
    # matcher has no explicit response_class, which is the case for all of our
    # mocks. Patching it here routes every mocked response through the subclass.
    _aioresponses_core.ClientResponse = _StreamWriterCompatClientResponse
