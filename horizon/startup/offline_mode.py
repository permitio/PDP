from typing import Optional, Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from pydantic import ValidationError
import base64
import secrets

from horizon.startup.schemas import RemoteConfig, RemoteConfigBackup
from opal_common.logger import logger


class OfflineModeManager:
    """
    A backup for the remote config, in case the sidecar can't fetch the remote config.
    """

    def __init__(self, backup_path: str, api_key: str):
        self._backup_path: str = backup_path
        self._api_key = api_key

    def _derive_backup_key(self, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = secrets.token_bytes(16)
        else:
            salt = base64.urlsafe_b64decode(salt)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"Sidecar's local remote-config backup Key",
            backend=default_backend(),
        )
        # We don't bother extracting the actual cryptographic bytes from the API key (which has a urlsafe encoding + a prefix),
        # The 512-bit entropy is still there, and HKDF's extract phase handles inputs of non-uniform randomness.
        key_bytes = hkdf.derive(self._api_key.encode("utf-8"))
        return base64.urlsafe_b64encode(key_bytes), base64.urlsafe_b64encode(salt)

    def backup_config(self, remote_config: RemoteConfig):
        # TODO: Don't use backup when remote config fetching fails due to an error which isn't a network error
        # TODO: Configure OPAL to use offline mode as well
        # TODO: Opal backup should be encrypted as well
        # TODO: Use a resaonable retry policy for fetching, should be configurable, should exit PDP if everything fails
        # TODO: Atomic writing the backup file

        logger.info(
            "Backing up remote config to {path}",
            path=self._backup_path,
        )

        enc_key, salt = self._derive_backup_key()

        with open(self._backup_path, "w") as f:
            f.write(
                RemoteConfigBackup(
                    enc_remote_config=Fernet(enc_key).encrypt(
                        remote_config.json(ensure_ascii=False).encode()
                    ),
                    key_derivation_salt=salt,
                ).json(ensure_ascii=False)
            )
        # TODO: Handle exceptions

    def restore_config(self) -> Optional[RemoteConfig]:
        logger.info(
            "Loading config from local backup at {path}",
            path=self._backup_path,
        )
        remote_config_backup: RemoteConfigBackup
        try:
            with open(self._backup_path, "r") as f:
                remote_config_backup = RemoteConfigBackup.parse_raw(f.read())
        except FileNotFoundError:
            logger.warning("Local backup file of sidecar config not found")
            return None
        except ValidationError:
            logger.error("Failed to parse backup remote config")
            return None

        dec_key, _ = self._derive_backup_key(remote_config_backup.key_derivation_salt)
        return RemoteConfig.parse_raw(
            Fernet(dec_key).decrypt(remote_config_backup.enc_remote_config)
        )

    def process_remote_config(
        self, remote_config: Optional[RemoteConfig]
    ) -> Optional[RemoteConfig]:
        if remote_config is None:
            # Cloud fetch failed, try to restore from backup
            remote_config = self.restore_config()
        else:
            # Cloud fetch succeeded, backup the fetched config
            self.backup_config(remote_config)

        # We handle enabling OPAL's offline mode in pdp.py
        return remote_config
