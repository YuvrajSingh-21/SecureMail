from enum import Enum, auto

class Severity(Enum):
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

class Confidence(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()

class VerdictBand(Enum):
    CLEAN = auto()
    SUSPICIOUS = auto()
    MALICIOUS = auto()
    UNKNOWN = auto()
