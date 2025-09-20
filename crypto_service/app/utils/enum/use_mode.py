from __future__ import annotations
from enum import Enum, auto

class UseMode(Enum):
    DERIV=auto()
    NORES=auto()
    BOTH=auto()
    ENCR=auto()
    DECR=auto()
    GEN=auto()
    VERIF=auto()
    COMB=auto()
    SIGN=auto()

    @staticmethod
    def get_use_mode(in_use_mode):
        if in_use_mode == UseMode.BOTH:
            ret = "B"
        elif in_use_mode == UseMode.DECR:
            ret = "D"
        elif in_use_mode == UseMode.ENCR:
            ret = "E"
        elif in_use_mode == UseMode.NORES:
            ret = "N"
        elif in_use_mode == UseMode.VERIF:
            ret = "S"
        elif in_use_mode == UseMode.GEN:
            ret = "G"
        elif in_use_mode == UseMode.COMB:
            ret = "C"
        elif in_use_mode == UseMode.SIGN:
            ret = "S"
        elif in_use_mode == UseMode.DERIV:
            ret = "X"
        else:
            raise ValueError("invalid use mode")
        return ret
    
    @staticmethod
    def get_str_use_mode(use_mode: str) -> UseMode:
        if use_mode == "BOTH":
            return UseMode.BOTH
        elif use_mode == "DERIV":
            return UseMode.DERIV
        elif use_mode == "ENCR":
            return UseMode.ENCR
        elif use_mode == "DECR":
            return UseMode.DECR
        elif use_mode == "GEN":
            return UseMode.GEN
        elif use_mode == "VERIF":
            return UseMode.VERIF
        elif use_mode == "SIGN":
            return UseMode.SIGN
        else:
            raise ValueError("invalid use mode")        