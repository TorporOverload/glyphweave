from enum import StrEnum


class ExtractionStatus(StrEnum):
    PENDING = "pending"
    DONE = "done"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"
