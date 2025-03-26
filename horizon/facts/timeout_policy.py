from enum import Enum


class TimeoutPolicy(str, Enum):
    IGNORE = "ignore"
    FAIL = "fail"
