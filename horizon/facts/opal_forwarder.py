from functools import cache
from urllib.parse import urljoin
from uuid import UUID, uuid4

from opal_common.fetcher.providers.http_fetch_provider import HttpFetcherConfig
from opal_common.schemas.data import DataSourceEntry, DataUpdate

from horizon.config import sidecar_config
from horizon.startup.remote_config import get_remote_config


@cache
def get_opal_data_base_url() -> str:
    remote_config = get_remote_config()
    org_id = remote_config.context.get("org_id")
    proj_id = remote_config.context.get("project_id")
    env_id = remote_config.context.get("env_id")
    return urljoin(
        sidecar_config.CONTROL_PLANE_PDP_DELTAS_API,
        f"v2/internal/opal_data/{org_id}/{proj_id}/{env_id}/",
    )


@cache
def get_opal_data_topic() -> str:
    remote_config = get_remote_config()
    pdp_client_id = remote_config.context.get("client_id")
    topic = f"{pdp_client_id}:data:policy_data"
    return topic


def create_data_source_entry(
    obj_type: str,
    obj_id: str,
    obj_key: str,
    authorization_header: str,
    *,
    update_id: UUID | None = None,
) -> DataSourceEntry:
    obj_id = obj_id.replace("-", "")  # convert UUID to Hex
    url = urljoin(
        get_opal_data_base_url(),
        f"{obj_type}/{obj_id}",
    )

    topic = get_opal_data_topic()

    headers = {
        "Authorization": authorization_header,
    }
    if sidecar_config.SHARD_ID:
        headers["X-Shard-Id"] = sidecar_config.SHARD_ID

    if update_id:
        headers["X-Permit-Update-Id"] = update_id.hex

    return DataSourceEntry(
        url=url,
        data=None,
        dst_path=f"{obj_type}/{obj_key}",
        save_method="PUT",
        topics=[topic],
        config=HttpFetcherConfig(headers=headers).dict(),
    )


def create_data_update_entry(
    entries: list[DataSourceEntry],
    *,
    update_id: UUID | None = None,
) -> DataUpdate:
    entries_text = ", ".join(entry.dst_path for entry in entries)
    _update_id = (update_id or uuid4()).hex

    if update_id is None:

        def inject_update_id(entry: DataSourceEntry) -> DataSourceEntry:
            entry_headers = entry.config.get("headers", {})
            entry_headers["X-Permit-Update-Id"] = _update_id
            entry.config["headers"] = entry_headers
            return entry

        entries = list(map(inject_update_id, entries))

    return DataUpdate(
        id=_update_id,
        entries=entries,
        reason=f"Local facts upload for {entries_text}",
    )
