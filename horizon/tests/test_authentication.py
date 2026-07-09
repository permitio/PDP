"""Unit tests for the PDP authentication dependencies.

Pure unit tests - no OpalClient, no PDP app build. Header parsing itself is now delegated
to ``fastapi.security.HTTPBearer`` (and exercised end-to-end with real header strings in
``test_opal_trigger_auth.py``), so these tests pin only what is genuinely ours: the
constant-time token comparison, the 401/503 contract of the two dependencies, and the
public-route allowlist that the route-audit test relies on.
"""

import horizon.authentication as auth
import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from horizon.authentication import (
    PUBLIC_ROUTE_PATHS,
    _token_matches,
    enforce_pdp_control_key,
    enforce_pdp_token,
)
from horizon.config import MOCK_API_KEY, sidecar_config

VALID_TOKEN = "s3cr3t-token"


def _creds(token: str) -> HTTPAuthorizationCredentials:
    """Build what HTTPBearer hands the dependency for a well-formed ``Bearer <token>``."""
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


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
