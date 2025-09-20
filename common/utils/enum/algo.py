from __future__ import annotations
from enum import Enum, auto

from common.middlewares.reqid_exception import BusinessLogicException

class Algo(Enum):
    TDES=auto()
    A128=auto()
    A192=auto()
    A256=auto()
    R2K=auto()
    R3K=auto()
    R4K=auto()
    ECP256=auto()
    ECP384=auto()
    ECP521=auto()
    S256R=auto()
    S256EC=auto()

    @staticmethod
    def get_algo(in_algo: Algo) -> str:
        if in_algo == Algo.A128:
            ret_algo = "A1"
        elif in_algo == Algo.TDES:
            ret_algo = "T2"
        elif in_algo == Algo.A192:
            ret_algo = "A2"
        elif in_algo == Algo.A256:
            ret_algo = "A3"
        elif in_algo in {Algo.S256R, Algo.R2K, Algo.R3K, Algo.R4K}:
            ret_algo = "01"
        elif in_algo in {Algo.S256EC, Algo.ECP256, Algo.ECP384, Algo.ECP521}:
            ret_algo = "02"
        else:
            raise BusinessLogicException(f"undefined algo {in_algo}")
        return ret_algo
    
    @staticmethod
    def get_str_algo(in_algo: str) -> Algo:
        if in_algo in ["ECP521", "ECP512"]:
            enm_algo = Algo.ECP521
        elif in_algo == "ECP384":
            enm_algo = Algo.ECP384
        elif in_algo == "ECP256":
            enm_algo = Algo.ECP256
        elif in_algo == "R2K":
            enm_algo = Algo.R2K
        elif in_algo == "R3K":
            enm_algo = Algo.R3K
        elif in_algo == "R4K":
            enm_algo = Algo.R4K
        elif in_algo == "A128":
            enm_algo = Algo.A128
        elif in_algo == "A192":
            enm_algo = Algo.A192
        elif in_algo == "A256":
            enm_algo = Algo.A256
        elif in_algo == "TDES":
            enm_algo = Algo.TDES
        else:
            raise BusinessLogicException(f"undefined algo {in_algo}")
        return enm_algo
    
    @staticmethod
    def get_algo_str(in_algo: Algo) -> str:
        if in_algo == Algo.R2K:
            algo = "R2K"
        elif in_algo == Algo.R3K:
            algo = "R3K"
        elif in_algo == Algo.R4K:
            algo = "R4K"
        elif in_algo == Algo.ECP256:
            algo = "ECP256"
        elif in_algo == Algo.ECP384:
            algo = "ECP384"
        elif in_algo == Algo.ECP521:
            algo = "ECP521"
        elif in_algo == Algo.A128:
            algo = "A128"
        elif in_algo == Algo.A192:
            algo = "A192"
        elif in_algo == Algo.A256:
            algo = "A256"
        elif in_algo == Algo.TDES:
            algo = "TDES"
        else:
            raise BusinessLogicException(f"undefined algo {in_algo}")
        return algo
