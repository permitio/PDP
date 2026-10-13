"""Keep request credentials out of the reprs of aiohttp's request objects.

opal-client logs ``repr()`` of the aiohttp errors its policy fetcher hits (policy/fetcher.py, once per
attempt and again when the retries run out) and stores it as the policy transaction error
(policy/updater.py). The policy store then logs that at ERROR and, with the health-check policy
enabled, writes it into OPA. Two kinds of those errors carry credentials in their repr:

* a ``ClientResponseError`` - a ``ContentTypeError`` whenever the server answers with a non-JSON
  body - embeds its ``RequestInfo``, and with it every request header, including the ``Authorization``
  one that carries the OPAL client token (PER-16823);
* a connector error raised while setting up TLS through an authenticated proxy (``HTTPS_PROXY`` with
  credentials: the fetcher trusts the environment) carries the request's ``ConnectionKey``, whose
  ``proxy_auth`` is a ``BasicAuth`` holding the proxy password.

No opal-client release logs these errors differently, and the PDP cannot move off 0.9.6 yet. So the
reprs of the two objects that carry the credentials are replaced, process-wide: that covers every one
of those call sites and sinks at once without patching OPAL itself. Header names, the auth scheme, the
proxy login, the URL and the method stay visible, so the errors stay debuggable. ``horizon.pdp``
installs this at import, before ``OpalClient`` can make a request.

The replacements must never raise: OPAL calls them inside ``except`` blocks, where an exception would
replace the error being reported. horizon/tests/test_aiohttp_redaction.py pins the aiohttp shapes this
relies on, and its canary fails once the reprs no longer leak without it.
"""

from collections.abc import Mapping

from aiohttp import BasicAuth, RequestInfo

# Header values shown as-is: the ones aiohttp and OPAL send besides credentials. Every other value
# is masked - an allowlist, because data-source and callback configs can add headers of any name.
LOGGABLE_HEADERS = frozenset({"accept", "accept-encoding", "content-length", "content-type", "host", "user-agent"})
# Kept in front of the mask, so a masked value still says which kind of credential was sent.
AUTH_SCHEMES = frozenset({"basic", "bearer", "digest", "negotiate", "token"})
MASK = "***"


def _masked_header_value(name: str, value: object) -> str:
    if name.lower() in LOGGABLE_HEADERS:
        return str(value)
    scheme, separator, _ = str(value).partition(" ")
    return f"{scheme} {MASK}" if separator and scheme.lower() in AUTH_SCHEMES else MASK


def _render_field(name: str, value: object) -> str:
    if isinstance(value, Mapping):
        headers = ", ".join(f"{key!r}: {_masked_header_value(str(key), item)!r}" for key, item in value.items())
        return f"<{type(value).__name__}({headers})>"
    # Fail closed: headers that are not a mapping cannot be masked value by value.
    return MASK if name == "headers" else repr(value)


def redacted_request_info_repr(self: RequestInfo) -> str:
    """aiohttp's NamedTuple repr, with every header value outside ``LOGGABLE_HEADERS`` masked."""
    try:
        fields = ", ".join(
            f"{name}={_render_field(name, value)}" for name, value in zip(self._fields, self, strict=True)
        )
    except Exception:  # noqa: BLE001 - a repr that raises would replace the error OPAL is reporting
        return f"{type(self).__name__}(<unrepresentable>)"
    return f"{type(self).__name__}({fields})"


def redacted_basic_auth_repr(self: BasicAuth) -> str:
    """aiohttp's namedtuple repr, with the password masked."""
    return f"{type(self).__name__}(login={self.login!r}, password={MASK!r}, encoding={self.encoding!r})"


def install() -> None:
    """Mask credentials in every ``RequestInfo`` and ``BasicAuth`` repr in this process. Idempotent."""
    RequestInfo.__repr__ = redacted_request_info_repr  # ty: ignore[invalid-assignment]  # only ever bound to RequestInfo
    BasicAuth.__repr__ = redacted_basic_auth_repr  # ty: ignore[invalid-assignment]  # only ever bound to BasicAuth
