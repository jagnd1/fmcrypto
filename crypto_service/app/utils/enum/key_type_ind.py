from enum import Enum, auto

class KeyTypeInd(Enum):
    SIGN = auto()
    KEY_MGMT = auto()
    BOTH = auto()
    ICC = auto()
    TLE = auto()
    PINED = auto()
    TR34_KWK = auto()
    TR34_SK = auto()
    KEY_AGR = auto()
    