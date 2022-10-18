import json
import os
from typing import Optional
from uuid import UUID, uuid4

from opal_common.logger import logger
from pydantic import BaseModel, ValidationError

PERSISTENT_STATE_FILENAME = "/persistent_state.json"


class PersistentState(BaseModel):
    pdp_instance_id: UUID


class PersistentStateHandler:
    _instance: Optional["PersistentStateHandler"] = None

    def __init__(self, filename: str):
        self._filename = filename
        if not self._load():
            self._new()

    def _new(self):
        self._state = PersistentState(
            pdp_instance_id=uuid4(),
        )

    def _load(self) -> bool:
        if os.path.exists(self._filename):
            with open(self._filename, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    logger.warning(
                        "Unable to load existing persistent state: Invalid JSON."
                    )
                    return False
            try:
                self._state = PersistentState(**data)
            except ValidationError:
                logger.warning(
                    "Unable to load existing persistent state: Invalid schema."
                )
                return False
            return True
        return False

    @classmethod
    def initialize(cls):
        cls._instance = cls(PERSISTENT_STATE_FILENAME)
        logger.info("PDP ID is {}", cls.get().pdp_instance_id)

    @classmethod
    def get(cls) -> "PersistentState":
        if cls._instance is None:
            raise RuntimeError("PersistentStateHandler not initialized.")
        return cls._instance._state
