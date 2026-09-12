from enum import Enum
from typing import Optional
from pydantic import BaseModel

from crypto_service.app.schema.crypto import Algo

class CertLevel(str, Enum):
    ROOT_CA = "ROOT_CA"
    INT_CA = "INT_CA"
    LEAF = "LEAF"

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