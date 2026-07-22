"""Unit tests for the PDP authentication dependencies.

Pure unit tests - no OpalClient, no PDP app build. Header parsing itself is now delegated
to ``fastapi.security.HTTPBearer`` (and exercised end-to-end with real header strings in
``test_opal_trigger_auth.py``), so these tests pin only what is genuinely ours: the
constant-time token comparison, the 401/503 contract of the two dependencies, and the
public-route allowlist that the route-audit test relies on.
"""

from types import SimpleNamespace

import horizon.authentication as auth
import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from horizon.authentication import (
    PUBLIC_ROUTE_PATHS,
    _token_matches,
    enforce_pdp_control_key,
    enforce_pdp_token,
    enforce_pdp_token_operational,
)
from horizon.config import MOCK_API_KEY, sidecar_config
from loguru import logger

VALID_TOKEN = "s3cr3t-token"


def _creds(token: str) -> HTTPAuthorizationCredentials:
    """Build what HTTPBearer hands the dependency for a well-formed ``Bearer <token>``."""
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _fake_request(path: str = "/policy-updater/trigger", method: str = "POST") -> SimpleNamespace:
    """A stand-in for the Request; the compat wrapper only reads ``.method`` and ``.url.path``."""
    return SimpleNamespace(method=method, url=SimpleNamespace(path=path))


@pytest.mark.parametrize(
    ("credentials", "expected"),
    [
        (_creds(VALID_TOKEN), True),
        (_creds("wrong-token"), False),
        (None, False),  # HTTPBearer(auto_error=False) yields None for missing/malformed headers
        (_creds(""), False),
        (_creds(f"{VALID_TOKEN} extra"), False),
    ],
)
def test_token_matches(credentials, expected):
    assert _token_matches(credentials, VALID_TOKEN) is expected


def test_token_matches_non_ascii_token():
    # Both operands are byte-encoded, so a matching non-ASCII token compares equal and a
    # non-ASCII mismatch does not raise (hmac.compare_digest would raise on non-ASCII str).
    assert _token_matches(_creds("ééé"), "ééé") is True
    assert _token_matches(_creds("ééé"), VALID_TOKEN) is False


class TestEnforcePdpToken:
    @pytest.fixture(autouse=True)
    def _patch_key(self, monkeypatch):
        monkeypatch.setattr(auth, "get_env_api_key", lambda: VALID_TOKEN)

    def test_missing_credentials_is_401(self):
        with pytest.raises(HTTPException) as exc:
            enforce_pdp_token(credentials=None)
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc.value.detail == "Missing Authorization header"

    def test_valid_token_passes(self):
        assert enforce_pdp_token(credentials=_creds(VALID_TOKEN)) is None

    def test_wrong_token_is_401(self):
        with pytest.raises(HTTPException) as exc:
            enforce_pdp_token(credentials=_creds("nope"))
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc.value.detail == "Invalid PDP token"


class TestEnforcePdpTokenOperational:
    """The ENFORCE_OPERATIONAL_ROUTE_AUTH wrapper: enforce when on, warn-and-allow when off (default)."""

    WARN_SUBSTRING = "ENFORCE_OPERATIONAL_ROUTE_AUTH is off"

    @pytest.fixture(autouse=True)
    def _patch_key(self, monkeypatch):
        monkeypatch.setattr(auth, "get_env_api_key", lambda: VALID_TOKEN)

    @pytest.fixture
    def enforce_on(self, monkeypatch):
        monkeypatch.setattr(sidecar_config, "ENFORCE_OPERATIONAL_ROUTE_AUTH", True)

    @pytest.fixture
    def enforce_off(self, monkeypatch):
        monkeypatch.setattr(sidecar_config, "ENFORCE_OPERATIONAL_ROUTE_AUTH", False)

    @pytest.mark.usefixtures("enforce_on")
    def test_enforce_on_missing_credentials_is_401(self):
        # Flag on: identical to enforce_pdp_token.
        with pytest.raises(HTTPException) as exc:
            enforce_pdp_token_operational(_fake_request(), credentials=None)
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc.value.detail == "Missing Authorization header"

    @pytest.mark.usefixtures("enforce_on")
    def test_enforce_on_wrong_token_is_401(self):
        with pytest.raises(HTTPException) as exc:
            enforce_pdp_token_operational(_fake_request(), credentials=_creds("nope"))
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc.value.detail == "Invalid PDP token"

    @pytest.mark.usefixtures("enforce_on")
    def test_enforce_on_valid_token_passes(self):
        assert enforce_pdp_token_operational(_fake_request(), credentials=_creds(VALID_TOKEN)) is None

    @pytest.mark.usefixtures("enforce_off")
    def test_enforce_off_missing_credentials_is_allowed_and_warns(self, capture_loguru):
        # The rollout default: a request that would be rejected is let through, but logged.
        assert enforce_pdp_token_operational(_fake_request(), credentials=None) is None
        assert any(self.WARN_SUBSTRING in record for record in capture_loguru)

    @pytest.mark.usefixtures("enforce_off")
    def test_enforce_off_wrong_token_is_allowed_and_warns(self, capture_loguru):
        assert enforce_pdp_token_operational(_fake_request(), credentials=_creds("nope")) is None
        assert any(self.WARN_SUBSTRING in record for record in capture_loguru)

    @pytest.mark.usefixtures("enforce_off")
    def test_enforce_off_valid_token_passes_without_warning(self, capture_loguru):
        # A caller that already sends the token is not flagged - only would-be rejections warn.
        assert enforce_pdp_token_operational(_fake_request(), credentials=_creds(VALID_TOKEN)) is None
        assert not any(self.WARN_SUBSTRING in record for record in capture_loguru)

    @pytest.mark.usefixtures("enforce_off")
    def test_enforce_off_coalesces_repeated_warnings(self, capture_loguru):
        # The warn-and-allow path must not log once per request (that floods the hot /kong endpoint):
        # a burst of would-be rejections on one route collapses to a single warning line.
        for _ in range(50):
            assert enforce_pdp_token_operational(_fake_request(path="/kong"), credentials=None) is None
        assert sum(self.WARN_SUBSTRING in record for record in capture_loguru) == 1

    @pytest.mark.usefixtures("enforce_off")
    def test_enforce_off_coalesces_per_route_not_globally(self, capture_loguru):
        # The throttle is keyed per route, not globally: a burst on /kong must not swallow the first
        # warning for a *different* route. A regression collapsing the throttle to one global key
        # would drop the second route's warning and this assertion would see only one line.
        for _ in range(5):
            enforce_pdp_token_operational(_fake_request(path="/kong"), credentials=None)
        for _ in range(5):
            enforce_pdp_token_operational(_fake_request(path="/policy-updater/trigger"), credentials=None)
        warnings = [record for record in capture_loguru if self.WARN_SUBSTRING in record]
        assert len(warnings) == 2  # one first-hit line per distinct route; the rest coalesced
        assert any("/kong" in record for record in warnings)
        assert any("/policy-updater/trigger" in record for record in warnings)

    @pytest.mark.usefixtures("enforce_off")
    def test_flush_residuals_surfaces_idle_route_tail(self, capture_loguru):
        # A route that falls idle mid-window strands the requests coalesced since its last warning;
        # the shutdown flush surfaces that tail so "the logs went quiet" cannot hide a lagging caller.
        for _ in range(5):
            enforce_pdp_token_operational(_fake_request(path="/kong"), credentials=None)
        # Only the first hit has been logged; the other four are pending and unreported.
        assert sum(self.WARN_SUBSTRING in record for record in capture_loguru) == 1
        auth.flush_operational_warn_residuals()
        flushed = [record for record in capture_loguru if self.WARN_SUBSTRING in record]
        assert len(flushed) == 2
        assert "flushing 4 further request(s)" in flushed[1]
        # Residual cleared: a second flush is a no-op.
        auth.flush_operational_warn_residuals()
        assert sum(self.WARN_SUBSTRING in record for record in capture_loguru) == 2


def test_operational_warn_coalesced_count_and_window_via_public_gate(monkeypatch, capture_loguru):
    """Count accuracy and the reported window, exercised through the public gate with a fake clock.

    Drives ``enforce_pdp_token_operational`` (not the private throttle) and asserts on the emitted log
    lines, so it pins the observable coalescing contract rather than the throttle's internal tuple
    shape - and crosses the interval by advancing a fake ``time.monotonic`` instead of sleeping.
    """
    monkeypatch.setattr(auth, "get_env_api_key", lambda: VALID_TOKEN)
    monkeypatch.setattr(sidecar_config, "ENFORCE_OPERATIONAL_ROUTE_AUTH", False)
    fake_clock = {"now": 1000.0}
    monkeypatch.setattr(auth.time, "monotonic", lambda: fake_clock["now"])

    # First would-be rejection emits immediately (count 1); the next four within the window coalesce.
    for _ in range(5):
        enforce_pdp_token_operational(_fake_request(path="/kong"), credentials=None)
    # Advance past the interval so the next hit flushes the coalesced total (the four held + this one).
    fake_clock["now"] += auth._OPERATIONAL_WARN_INTERVAL_SECONDS + 1
    enforce_pdp_token_operational(_fake_request(path="/kong"), credentials=None)

    warnings = [record for record in capture_loguru if "ENFORCE_OPERATIONAL_ROUTE_AUTH is off" in record]
    assert len(warnings) == 2
    assert "allowed 1 request(s)" in warnings[0]
    assert "allowed 5 request(s)" in warnings[1]
    # The reported window is the real elapsed span (~61s), not the fixed 60s interval.
    assert "in the last ~61s" in warnings[1]


@pytest.fixture
def capture_loguru():
    records: list[str] = []
    sink_id = logger.add(lambda message: records.append(str(message)), level="WARNING")
    yield records
    logger.remove(sink_id)


class TestEnforcePdpControlKey:
    CONTROL_KEY = "control-key"

    def test_disabled_when_unset_returns_503(self, monkeypatch):
        monkeypatch.setattr(sidecar_config, "CONTAINER_CONTROL_KEY", MOCK_API_KEY)
        # 503 takes precedence over any credential state, including missing credentials.
        with pytest.raises(HTTPException) as exc:
            enforce_pdp_control_key(credentials=None)
        assert exc.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    def test_enabled_missing_credentials_is_401(self, monkeypatch):
        monkeypatch.setattr(sidecar_config, "CONTAINER_CONTROL_KEY", self.CONTROL_KEY)
        with pytest.raises(HTTPException) as exc:
            enforce_pdp_control_key(credentials=None)
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc.value.detail == "Missing Authorization header"

    def test_enabled_correct_key_passes(self, monkeypatch):
        monkeypatch.setattr(sidecar_config, "CONTAINER_CONTROL_KEY", self.CONTROL_KEY)
        assert enforce_pdp_control_key(credentials=_creds(self.CONTROL_KEY)) is None

    def test_enabled_wrong_key_is_401(self, monkeypatch):
        monkeypatch.setattr(sidecar_config, "CONTAINER_CONTROL_KEY", self.CONTROL_KEY)
        with pytest.raises(HTTPException) as exc:
            enforce_pdp_control_key(credentials=_creds("wrong"))
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc.value.detail == "Invalid PDP token"


def test_public_route_paths_contents():
    assert isinstance(PUBLIC_ROUTE_PATHS, frozenset)
    assert "/health" in PUBLIC_ROUTE_PATHS
    # Protected paths must never leak into the public allowlist.
    for protected in (
        "/healthchecks/opa/ready",  # the /health prefix trap
        "/policy-updater/trigger",
        "/data-updater/trigger",
        "/kong",
        "/version",
    ):
        assert protected not in PUBLIC_ROUTE_PATHS
