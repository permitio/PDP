from enum import StrEnum


class TimeoutPolicy(StrEnum):
    IGNORE = "ignore"
    FAIL = "fail"
