"""Secrets in the PDP's settings stay out of the printed config and the startup log.

``PDP_PRINT_CONFIG_ON_STARTUP`` logs ``debug_repr()`` of the sidecar config and of OPAL's client
and common config. The secret settings print as ``<redacted>``, and a credential embedded in a URL
setting is masked while the host stays readable. Every key below is fake.
"""

import io
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

import pytest
from loguru import logger
from opal_client.config import opal_client_config, opal_common_config
from opal_common.fetcher.providers.http_fetch_provider import HttpFetcherConfig
from opal_common.logger import configure_logs
from opal_common.schemas.data import CallbackEntry

from horizon import pdp
from horizon.config import sidecar_config
from horizon.enforcer.opa import config_maker
from horizon.startup.schemas import RemoteConfig
from horizon.state import PersistentStateHandler

# How confi prints a sensitive entry's value.
REDACTED = "<redacted>"

FAKE_ENV_API_KEY = "permit_key_FakeEnvApiKey0123456789"
FAKE_SECRETS = {
    "API_KEY": FAKE_ENV_API_KEY,
    "ORG_API_KEY": "permit_key_FakeOrgApiKey0123456789",
    "PROJECT_API_KEY": "permit_key_FakeProjectApiKey012345",
    "CONTAINER_CONTROL_KEY": "fake-container-control-key-0123",
    "CENTRAL_LOG_TOKEN": "fake-central-log-token-0123456",
}
FAKE_CALLBACK_KEY = "fake-data-callback-key-0123456"
FAKE_PLUGIN_TOKEN = "fake-opa-plugin-token-01234567"
FAKE_URL_PASSWORD = "fake-url-password-0123456789"
FAKE_URL_TOKEN = "fake-url-query-token-012345678"
# The control plane sends these two in the opal_client section of the remote config.
FAKE_OPAL_CLIENT_TOKEN = "fake-opal-client-token-0123456"
FAKE_CALLBACK_BEARER = "FakeControlPlaneCallbackBearer0123"

SECRET_VALUES = [
    *FAKE_SECRETS.values(),
    FAKE_CALLBACK_KEY,
    FAKE_PLUGIN_TOKEN,
    FAKE_URL_PASSWORD,
    FAKE_URL_TOKEN,
    FAKE_OPAL_CLIENT_TOKEN,
    FAKE_CALLBACK_BEARER,
]
SECRET_SETTINGS = [*FAKE_SECRETS, "DATA_UPDATE_CALLBACKS", "OPA_PLUGINS"]


def _unmasked(texts: list[str]) -> list[str]:
    return [value for value in SECRET_VALUES if any(value in text for text in texts)]


@pytest.fixture
def restored_configs(monkeypatch) -> None:
    """Restore every setting of the three configs the PDP prints, whatever the test changes."""
    for config in (sidecar_config, opal_client_config, opal_common_config):
        for key in list(config.entries):
            monkeypatch.setattr(config, key, getattr(config, key))


@pytest.fixture
def secrets_set(monkeypatch, restored_configs) -> None:  # noqa: ARG001 - restores what this sets
    for key, value in FAKE_SECRETS.items():
        monkeypatch.setattr(sidecar_config, key, value)
    callback = CallbackEntry(
        url="http://callback.example.invalid/data",
        config=HttpFetcherConfig(headers={"X-Api-Key": FAKE_CALLBACK_KEY}),
    )
    monkeypatch.setattr(sidecar_config, "DATA_UPDATE_CALLBACKS", [callback])
    monkeypatch.setattr(sidecar_config, "OPA_PLUGINS", {"vault_secrets": {"token": FAKE_PLUGIN_TOKEN}})
    monkeypatch.setattr(
        sidecar_config,
        "CONTROL_PLANE",
        f"https://pdp:{FAKE_URL_PASSWORD}@control-plane.example.invalid/?token={FAKE_URL_TOKEN}",
    )


def _printed_line(rendered: str, key: str) -> str:
    return next(line.strip() for line in rendered.splitlines() if line.strip().startswith(f"{key}:"))


@pytest.mark.usefixtures("secrets_set")
def test_debug_repr_and_repr_hold_no_secret():
    assert _unmasked([sidecar_config.debug_repr(), repr(sidecar_config)]) == []


@pytest.mark.usefixtures("secrets_set")
@pytest.mark.parametrize("key", SECRET_SETTINGS)
def test_a_secret_setting_prints_as_redacted(key: str):
    assert _printed_line(sidecar_config.debug_repr(), key) == f"{key}: {REDACTED}"


@pytest.mark.usefixtures("secrets_set")
def test_a_credential_in_a_url_setting_is_masked_and_the_host_stays_readable():
    line = _printed_line(sidecar_config.debug_repr(), "CONTROL_PLANE")

    assert "control-plane.example.invalid" in line
    assert FAKE_URL_PASSWORD not in line
    assert FAKE_URL_TOKEN not in line


@dataclass
class StartupOutput:
    """What PermitPDP() logged before it would start OPAL."""

    #: What the PDP's startup logger wrote.
    stdout: io.StringIO = field(default_factory=io.StringIO)
    #: Every record as plain text and as the JSON a serializing sink writes, extras included.
    records: list[str] = field(default_factory=list)


class _StopBeforeOpalError(Exception):
    """Raised where PermitPDP starts OPAL, after it printed its config."""


@pytest.fixture
def startup(monkeypatch, tmp_path: Path, secrets_set) -> Iterator[StartupOutput]:  # noqa: ARG001 - sets the secrets
    """PermitPDP() with the control plane answered locally, stopped where it would start OPAL."""
    remote_config = RemoteConfig(
        opal_client={
            "CLIENT_TOKEN": FAKE_OPAL_CLIENT_TOKEN,
            # The shape the control plane sends: a report callback that authenticates with a bearer.
            "DEFAULT_UPDATE_CALLBACKS": {
                "callbacks": [
                    [
                        "https://control-plane.example.invalid/v2/pdps/me/opal_data_callback",
                        {
                            "method": "post",
                            "headers": {
                                "content-type": "application/json",
                                "authorization": f"Bearer {FAKE_CALLBACK_BEARER}",
                            },
                            "process_data": False,
                        },
                    ]
                ]
            },
        },
        context={
            "org_id": "11111111-1111-1111-1111-111111111111",
            "project_id": "22222222-2222-2222-2222-222222222222",
            "env_id": "33333333-3333-3333-3333-333333333333",
        },
    )
    output = StartupOutput()
    setup_temp_logger = pdp.PermitPDP._setup_temp_logger

    def setup_temp_logger_then_capture(self: pdp.PermitPDP) -> None:
        # The startup sink keeps the stream it was given. Patched here, not in the fixture, because
        # pytest's own capture sets sys.stdout again before the test runs.
        with patch.object(sys, "stdout", output.stdout):
            setup_temp_logger(self)  # replaces every sink with the startup sink
        logger.add(output.records.append, format="{message} | {extra}", level="DEBUG")
        logger.add(output.records.append, serialize=True, level="DEBUG")

    def stop_before_opal(**_kwargs) -> None:
        raise _StopBeforeOpalError

    monkeypatch.setattr(sidecar_config, "PRINT_CONFIG_ON_STARTUP", True)
    monkeypatch.setattr(sidecar_config, "HORIZON_NICENESS", 0)
    monkeypatch.setattr(sidecar_config, "OPA_CONFIG_FILE_PATH", str(tmp_path / "opa" / "config.yaml"))
    monkeypatch.setattr(sidecar_config, "OPA_AUTH_POLICY_FILE_PATH", str(tmp_path / "opa" / "basic-authz.rego"))
    monkeypatch.setattr(pdp.PermitPDP, "_setup_temp_logger", setup_temp_logger_then_capture)
    monkeypatch.setattr(pdp, "hand_off_env_api_key", lambda: None)
    monkeypatch.setattr(pdp, "get_env_api_key", lambda: FAKE_ENV_API_KEY)
    monkeypatch.setattr(config_maker, "get_env_api_key", lambda: FAKE_ENV_API_KEY)
    monkeypatch.setattr(PersistentStateHandler, "_instance", None)
    monkeypatch.setattr(pdp, "get_remote_config", lambda: remote_config)
    monkeypatch.setattr(pdp, "OpalClient", stop_before_opal)
    # Another test's OpalClient may have installed OPAL's record patcher, which masks some
    # credentials for every sink. At startup the PDP logs before OPAL configures logging.
    logger.configure(patcher=lambda _record: None)
    yield output
    # Leave logging the way an OpalClient leaves it, as the other tests found it.
    configure_logs()


def test_the_startup_config_print_holds_no_secret(startup: StartupOutput):
    with pytest.raises(_StopBeforeOpalError):
        pdp.PermitPDP()

    printed = [record for record in startup.records if "sidecar is loading with the following config" in record]
    # One plain-text record and one serialized record.
    assert len(printed) == 2
    # What the PDP set from the API key and the remote config is what was printed, redacted.
    assert opal_client_config.POLICY_STORE_AUTH_TOKEN == FAKE_ENV_API_KEY
    assert opal_client_config.CLIENT_TOKEN == FAKE_OPAL_CLIENT_TOKEN
    for key in ("POLICY_STORE_AUTH_TOKEN", "CLIENT_TOKEN"):
        assert f"{key}: {REDACTED}" in printed[0]
    assert "DEFAULT_UPDATE_CALLBACKS:" in printed[0]
    assert _unmasked(printed) == []


def test_the_startup_log_holds_no_secret(startup: StartupOutput):
    with pytest.raises(_StopBeforeOpalError):
        pdp.PermitPDP()

    written = startup.stdout.getvalue()
    # This line prints the decision log upload URL: CONTROL_PLANE, which carries credentials here.
    assert "Writing the OPA config file: decision log upload to https://" in written
    assert "sidecar is loading with the following config" in written
    assert _unmasked([written]) == []
