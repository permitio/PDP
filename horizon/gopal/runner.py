import os
import platform
from pathlib import Path

from opal_client.engine.runner import PolicyEngineRunner

from horizon.config import sidecar_config


class GopalRunner(PolicyEngineRunner):

    @property
    def command(self) -> str:
        current_dir = Path(__file__).parent
        os.environ["PDP_ENGINE_TOKEN"] = sidecar_config.API_KEY
        arch = platform.machine()
        if arch == 'x86_64':
            binary_path = 'gopal-amd'
        elif arch == 'arm64' or arch == 'aarch64':
            binary_path = 'gopal-arm'
        else:
            raise ValueError(f"Unsupported architecture: {arch}")
        return os.path.join(current_dir, binary_path)
