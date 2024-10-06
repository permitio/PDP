from pydantic import BaseModel


class RemoteConfig(BaseModel):
    opal_common: dict = {}
    opal_client: dict = {}
    pdp: dict = {}
    context: dict = {}


class RemoteConfigBackup(BaseModel):
    """
    A backup for the remote config, in case the sidecar can't fetch the remote config.
    """

    enc_remote_config: bytes
    key_derivation_salt: bytes
