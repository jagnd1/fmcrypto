from __future__ import annotations
from enum import Enum, auto


class CertLevel(Enum):
    ROOT_CA=auto()
    INT_CA=auto()
    LEAF=auto()

    @staticmethod
    def get_cert_level(in_cert_level: str) -> CertLevel:
        if in_cert_level == "ROOT_CA":
            enm_cert_level = CertLevel.ROOT_CA
        elif in_cert_level == "INT_CA":
            enm_cert_level = CertLevel.INT_CA
        elif in_cert_level == "LEAF":
            enm_cert_level = CertLevel.LEAF
        return enm_cert_level

    @staticmethod
    def get_cert_level_str(in_cert_level: CertLevel) -> str:
        if in_cert_level == CertLevel.ROOT_CA:
            cert_level = "ROOT_CA"
        elif in_cert_level == CertLevel.INT_CA:
            cert_level = "INT_CA"
        elif in_cert_level == CertLevel.LEAF:
            cert_level = "LEAF"
        return cert_level
