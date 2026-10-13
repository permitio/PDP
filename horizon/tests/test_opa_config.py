"""What the PDP hands OPA: the OPA config file, and the inline OPA config OPAL starts OPA with.

OPA reads decision log and plugin settings only from its config file. The file used to be written
only with decision logs on, so a PDP with them off never loaded its plugins (permit_graph among
them) and its ReBAC user permissions came back empty.
"""

import itertools
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import NamedTuple

import pytest
import yaml
from loguru import logger
from opal_client.config import EngineLogFormat, opal_client_config, opal_common_config
from opal_client.engine.options import OpaServerOptions

from horizon.config import sidecar_config
from horizon.enforcer.opa import config_maker
from horizon.enforcer.opa.config_maker import get_opa_config_file_path
from horizon.pdp import OPA_LOGGER_MODULE, PermitPDP

API_KEY = "test-pdp-api-key"
BACKEND_TIER = "https://logs.example.test"
PLUGINS: dict[str, dict[str, int | bool | str]] = {
    "permit_graph": {},
    "envoy_ext_authz_grpc": {"addr": ":9191", "path": "permit/root"},
}


class OpaSettings(NamedTuple):
    decision_logs: bool
    plugins: dict[str, dict[str, int | bool | str]]
    bearer_required: bool
    console: bool = False

    @property
    def id(self) -> str:
        return "-".join(
            [
                "decision-logs" if self.decision_logs else "no-decision-logs",
                "plugins" if self.plugins else "no-plugins",
                "bearer-required" if self.bearer_required else "bearer-optional",
                "console" if self.console else "no-console",
            ]
        )


ALL_SETTINGS = [
    OpaSettings(decision_logs, plugins, bearer_required, console)
    for decision_logs, plugins, bearer_required, console in itertools.product(
        [True, False], [PLUGINS, {}], [True, False], [True, False]
    )
]
CONFIG_FILE_SETTINGS = [
    settings for settings in ALL_SETTINGS if settings.decision_logs or settings.plugins or settings.console
]


@pytest.fixture
def opa_files(monkeypatch, tmp_path) -> SimpleNamespace:
    """Write the OPA files under tmp_path, and answer the API key lookup without a control plane."""
    files = SimpleNamespace(config=tmp_path / "opa" / "config.yaml", authz=tmp_path / "opa" / "basic-authz.rego")
    monkeypatch.setattr(sidecar_config, "OPA_CONFIG_FILE_PATH", str(files.config))
    monkeypatch.setattr(sidecar_config, "OPA_AUTH_POLICY_FILE_PATH", str(files.authz))
    monkeypatch.setattr(sidecar_config, "OPA_DECISION_LOG_INGRESS_BACKEND_TIER_URL", BACKEND_TIER)
    monkeypatch.setattr(config_maker, "get_env_api_key", lambda: API_KEY)
    monkeypatch.setattr("horizon.pdp.get_env_api_key", lambda: API_KEY)
    return files


@pytest.fixture
def inline_opa_config(monkeypatch) -> OpaServerOptions:
    """The image's OPAL_INLINE_OPA_CONFIG. The OPAL settings the PDP may change are restored after."""
    shipped = OpaServerOptions(v0_compatible=True)
    monkeypatch.setattr(opal_client_config, "INLINE_OPA_CONFIG", shipped)
    monkeypatch.setattr(opal_client_config, "POLICY_STORE_AUTH_TOKEN", opal_client_config.POLICY_STORE_AUTH_TOKEN)
    monkeypatch.setattr(opal_client_config, "POLICY_STORE_AUTH_TYPE", opal_client_config.POLICY_STORE_AUTH_TYPE)
    monkeypatch.setattr(opal_client_config, "INLINE_OPA_LOG_FORMAT", EngineLogFormat.NONE)
    monkeypatch.setattr(opal_common_config, "LOG_MODULE_EXCLUDE_LIST", ["uvicorn", OPA_LOGGER_MODULE])
    return shipped


@pytest.fixture
def logged_warnings() -> Iterator[list[str]]:
    """Every loguru message at WARNING or above emitted during the test."""
    messages: list[str] = []
    sink_id = logger.add(lambda message: messages.append(message.record["message"]), level="WARNING")
    yield messages
    logger.remove(sink_id)


def _configure(monkeypatch, settings: OpaSettings) -> None:
    monkeypatch.setattr(sidecar_config, "OPA_DECISION_LOG_ENABLED", settings.decision_logs)
    monkeypatch.setattr(sidecar_config, "OPA_PLUGINS", settings.plugins)
    monkeypatch.setattr(sidecar_config, "OPA_BEARER_TOKEN_REQUIRED", settings.bearer_required)
    monkeypatch.setattr(sidecar_config, "OPA_DECISION_LOG_CONSOLE", settings.console)


def _expected_config(settings: OpaSettings) -> dict:
    expected: dict = {}
    if settings.decision_logs:
        expected["services"] = {
            "permit_io": {"url": BACKEND_TIER, "credentials": {"bearer": {"token": API_KEY}}},
        }
    if settings.decision_logs or settings.console:
        expected["decision_logs"] = {}
    if settings.console:
        expected["decision_logs"]["console"] = True
    if settings.decision_logs:
        expected["decision_logs"] |= {
            "service": "permit_io",
            "resource": sidecar_config.OPA_DECISION_LOG_INGRESS_ROUTE,
            "reporting": {
                "min_delay_seconds": sidecar_config.OPA_DECISION_LOG_MIN_DELAY,
                "max_delay_seconds": sidecar_config.OPA_DECISION_LOG_MAX_DELAY,
                "upload_size_limit_bytes": sidecar_config.OPA_DECISION_LOG_UPLOAD_SIZE_LIMIT,
            },
        }
    if settings.plugins:
        # A plugin with an empty config is written as `permit_graph:`, which YAML reads as null.
        expected["plugins"] = {
            plugin_id: plugin_config or None for plugin_id, plugin_config in settings.plugins.items()
        }
    return expected


def _configure_inline_opa_config() -> OpaServerOptions:
    PermitPDP._configure_inline_opa_config()
    return opal_client_config.INLINE_OPA_CONFIG


@pytest.mark.parametrize("settings", ALL_SETTINGS, ids=lambda settings: settings.id)
def test_the_config_file_holds_what_is_enabled(monkeypatch, opa_files, settings: OpaSettings):
    # Whether callers of OPA need a bearer token does not change the file: the permit_io
    # credentials are what OPA uploads decision logs with.
    _configure(monkeypatch, settings)

    path = get_opa_config_file_path(sidecar_config)

    assert path == str(opa_files.config)
    contents = Path(path).read_text()
    assert (yaml.safe_load(contents) or {}) == _expected_config(settings)
    assert (API_KEY in contents) == settings.decision_logs


@pytest.mark.usefixtures("inline_opa_config")
@pytest.mark.parametrize("settings", CONFIG_FILE_SETTINGS, ids=lambda settings: settings.id)
def test_opa_gets_the_config_file_when_decision_logs_console_or_plugins_are_on(
    monkeypatch, opa_files, settings: OpaSettings
):
    _configure(monkeypatch, settings)

    configured = _configure_inline_opa_config()

    assert configured.config_file == str(opa_files.config)
    assert yaml.safe_load(opa_files.config.read_text()) == _expected_config(settings)
    assert configured.authentication == ("token" if settings.bearer_required else "off")
    assert configured.v0_compatible is True  # the image's own setting is kept
    # Console decision logs reach the PDP's output only with OPA's log lines shown.
    shown = opal_client_config.INLINE_OPA_LOG_FORMAT == EngineLogFormat.FULL
    assert shown == settings.console
    assert (OPA_LOGGER_MODULE not in opal_common_config.LOG_MODULE_EXCLUDE_LIST) == settings.console


@pytest.mark.usefixtures("inline_opa_config")
def test_a_required_bearer_token_alone_writes_no_config_file(monkeypatch, opa_files):
    _configure(monkeypatch, OpaSettings(decision_logs=False, plugins={}, bearer_required=True))

    configured = _configure_inline_opa_config()

    assert configured.config_file is None
    assert not opa_files.config.exists()
    assert configured.authentication == "token"
    assert configured.files == [str(opa_files.authz)]
    assert configured.v0_compatible is True  # the image's own setting is kept


def test_with_nothing_to_add_the_inline_config_is_left_as_it_is(monkeypatch, opa_files, inline_opa_config):
    _configure(monkeypatch, OpaSettings(decision_logs=False, plugins={}, bearer_required=False))

    configured = _configure_inline_opa_config()

    assert configured is inline_opa_config
    assert not opa_files.config.exists()


@pytest.mark.usefixtures("inline_opa_config")
def test_a_different_config_file_in_the_inline_config_is_replaced_with_a_warning(
    monkeypatch, opa_files, logged_warnings
):
    user_config_file = "/etc/opa/user-config.yaml"
    monkeypatch.setattr(
        opal_client_config, "INLINE_OPA_CONFIG", OpaServerOptions(v0_compatible=True, config_file=user_config_file)
    )
    _configure(monkeypatch, OpaSettings(decision_logs=False, plugins=PLUGINS, bearer_required=False))

    configured = _configure_inline_opa_config()

    assert configured.config_file == str(opa_files.config)
    assert len(logged_warnings) == 1
    assert user_config_file in logged_warnings[0]
    assert str(opa_files.config) in logged_warnings[0]


@pytest.mark.usefixtures("inline_opa_config")
def test_the_pdp_config_file_already_in_the_inline_config_is_kept_without_a_warning(
    monkeypatch, opa_files, logged_warnings
):
    monkeypatch.setattr(
        opal_client_config, "INLINE_OPA_CONFIG", OpaServerOptions(v0_compatible=True, config_file=str(opa_files.config))
    )
    _configure(monkeypatch, OpaSettings(decision_logs=False, plugins=PLUGINS, bearer_required=False))

    configured = _configure_inline_opa_config()

    assert configured.config_file == str(opa_files.config)
    assert logged_warnings == []
