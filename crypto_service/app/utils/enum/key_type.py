from __future__ import annotations
from enum import Enum, auto

class KeyType(Enum):
    ZPK=auto()
    PVK=auto()
    CVK=auto()
    MKAC=auto()
    BDK=auto()
    ZMK=auto()
    TMK=auto()
    TEK=auto()
    DEK=auto()
    PEK=auto()
    MEK=auto()

    @staticmethod
    def get_key_type(in_key_type: KeyType) -> str:
        if in_key_type == KeyType.ZPK:
            key_usage = "72"
        elif in_key_type == KeyType.CVK:
            key_usage = "13"
        elif in_key_type == KeyType.PVK:
            key_usage = "V2"
        elif in_key_type == KeyType.MKAC:
            key_usage = "E0"
        elif in_key_type == KeyType.BDK:
            key_usage = "B0"
        elif in_key_type == KeyType.ZMK:
            key_usage = "52"
        elif in_key_type == KeyType.TMK:
            key_usage = "51"
        elif in_key_type == KeyType.TEK:
            key_usage = "23"
        elif in_key_type == KeyType.PEK:
            key_usage = "23"
        elif in_key_type == KeyType.DEK:
            key_usage = "21"
        return key_usage 
    
    @staticmethod
    def get_str_key_type(in_key_type: str) -> KeyType:
        if in_key_type == "TMK":
            return KeyType.TMK
        if in_key_type == "ZPK":
            return KeyType.ZPK
        if in_key_type == "CVK":
            return KeyType.CVK
        if in_key_type == "PVK":
            return KeyType.PVK
        if in_key_type == "MKAC":
            return KeyType.MKAC
        if in_key_type == "BDK":
            return KeyType.BDK
        if in_key_type == "ZMK":
            return KeyType.ZMK
        if in_key_type == "TEK":
            return KeyType.TEK
        if in_key_type == "PEK":
            return KeyType.PEK
        if in_key_type == "DEK":
            return KeyType.DEK




