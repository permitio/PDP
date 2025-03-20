from pydantic import BaseModel, Field


class RemoteConfig(BaseModel):
    opal_common: dict = Field(default_factory=dict)
    opal_client: dict = Field(default_factory=dict)
    pdp: dict = Field(default_factory=dict)
    context: dict = Field(default_factory=dict)


class RemoteConfigBackup(BaseModel):
    """
    A backup for the remote config, in case the sidecar can't fetch the remote config.
    """

    enc_remote_config: bytes
    key_derivation_salt: bytes
