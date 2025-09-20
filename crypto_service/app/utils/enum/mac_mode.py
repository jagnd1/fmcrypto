
from __future__ import annotations
from enum import Enum, auto


class MacMode(Enum):
    GENERATE=auto()
    VERIFY=auto()

    @staticmethod
    def get_str_mac_mode(in_mac_mode: str) -> MacMode:
        if in_mac_mode == "GENERATE":
            return MacMode.GENERATE
        elif in_mac_mode == "VERIFY":
            return MacMode.VERIFY
        else:
            raise ValueError("invalid mac mode")