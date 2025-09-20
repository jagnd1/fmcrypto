
from enum import Enum
from typing import Optional
from pydantic import BaseModel

    
class CertLevel(str, Enum):
    ROOT_CA = "ROOT_CA"
    INT_CA = "INT_CA"
    LEAF = "LEAF"

class Algo(str, Enum):
    TDES = "TDES"
    A128 = "A128"
    A192 = "A192"
    A256 = "A256"
    R2K = "R2K"
    R3K = "R3K"
    R4K = "R4K"
    ECP256 = "ECP256"
    ECP384 = "ECP384"
    ECP512 = "ECP512"
    ECP521 = "ECP521"

class CertCreateReq(BaseModel):
    csr: str
    issuer_cert: Optional[str] = None
    sk_lmk: str
    cert_level: CertLevel
    algo: Algo

class CertResp(BaseModel):
    status: str
    cert: Optional[str] = None
    class Config:
        from_attributes = True

class CertUpdate(BaseModel):
    cert: str
    issuer_cert: str
    sk_lmk: str
    cert_level: CertLevel
    algo: Algo


class CrlMgmtReq(BaseModel):
    cert: str
    issuer_cert: str
    sk_lmk: str
    algo: Algo
    crl: Optional[str] = None

class CrlMgmtResp(BaseModel):
    status: str
    crl: Optional[str] = None
    class Config:
        from_attributes = True
