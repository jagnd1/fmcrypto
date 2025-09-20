from enum import Enum
from typing import Optional
from pydantic import BaseModel

class UseMode(str, Enum):
    DERIV = "DERIV"
    NORES = "NORES"
    BOTH = "BOTH"
    ENCR = "ENCR"
    DECR = "DECR"
    GEN = "GEN"
    VERIF = "VERIF"
    COMB = "COMB"
    SIGN = "SIGN"

class Algo(str, Enum):
    R2K = "R2K"
    R3K = "R3K"
    R4K = "R4K"
    ECP256 = "ECP256"
    ECP384 = "ECP384"
    ECP512 = "ECP512"
    ECP521 = "ECP521"
    A128 = "A128"
    A192 = "A192"
    A256 = "A256"
    TDES = "TDES"

class KpGenReq(BaseModel):
    algo: Algo
    use_mode: UseMode

class KpGenResp(BaseModel):
    status: str
    pk: Optional[str] = None
    sk_lmk: Optional[str] = None
    class Config:
        from_attributes = True

class SignReq(BaseModel):
    msg: str
    sk_lmk: str
    algo: Algo

class SignResp(BaseModel):
    status: str
    signature: Optional[str] = None
    class Config:
        from_attributes = True
    

class KeyType(str, Enum):
    ZPK = "ZPK"
    PVK = "PVK"
    CVK = "CVK"
    MKAC = "MKAC"
    BDK = "BDK"
    ZMK = "ZMK"
    TMK = "TMK"
    TEK = "TEK"
    DEK = "DEK"
    PEK = "PEK"
    MEK = "MEK"

class EcdhReq(BaseModel):
    eph_pk: str
    algo: Algo
    key_type: KeyType
    use_mode: UseMode
    shared_info: Optional[str] = None

class EcdhResp(BaseModel):
    status: str
    derived_key: Optional[str] = None
    kcv: Optional[str] = None
    recp_eph_pk: Optional[str] = None
    class Config:
        from_attributes = True


class ExpKeyReq(BaseModel):
    key_lmk: str
    kcv: str
    pk: str

class ExpKeyResp(BaseModel):
    status: str
    key_pk: Optional[str] = None
    class Config:
        from_attributes = True


class ExpTr34Req(BaseModel):
    kbpk: str
    kcv: str
    kdh_cert: str
    krd_cert: str
    kdh_sk_lmk: str

class ExpTr34Resp(BaseModel):
    status: str
    aa: Optional[str] = None
    ed: Optional[str] = None
    signature: Optional[str] = None
    class Config:
        from_attributes = True

class RandGenReq(BaseModel):
    len: str

class RandGenResp(BaseModel):
    status: str
    rand_no: Optional[str] = None
    class Config:
        from_attributes = True


class KeyGenReq(BaseModel):
    key_type: KeyType
    use_mode: UseMode
    algo: Algo
    exp_key: Optional[str] = None

class KeyGenResp(BaseModel):
    status: str
    key_lmk: Optional[str] = None
    kcv: Optional[str] = None
    class Config:
        from_attributes = True


class KcvGenReq(BaseModel):
    key_lmk: str

class KcvGenResp(BaseModel):
    status: str
    kcv: Optional[str] = None
    class Config:
        from_attributes = True


class IpekDeriveReq(BaseModel):
    bdk_lmk: str
    iksn: str
    tk: Optional[str] = None
    algo: Algo
    use_mode: UseMode

class IpekDeriveResp(BaseModel):
    status: str
    ipek_lmk: Optional[str] = None
    ipek_tk: Optional[str] = None
    kcv: Optional[str] = None
    class Config:
        from_attributes = True

class EncrMode(str, Enum):
    CBC = "CBC"
    ECB = "ECB"
    CBC_PAD = "CBC_PAD"

class DataEncrReq(BaseModel):
    key_lmk: str
    ksn: Optional[str] = None
    iv: Optional[str] = None
    encr_mode: EncrMode
    msg: str
    algo: Algo

class DataEncrResp(BaseModel):
    status: str
    encr_msg: Optional[str] = None
    class Config:
        from_attributes = True


class DataDecrReq(BaseModel):
    key_lmk: str
    ksn: Optional[str] = None
    iv: Optional[str] = None
    encr_mode: Optional[EncrMode] = None
    encr_msg: str
    algo: Algo

class DataDecrResp(BaseModel):
    status: str
    msg: Optional[str] = None
    class Config:
        from_attributes = True


class MacMode(str, Enum):
    GENERATE = "GENERATE"
    VERIFY = "VERIFY"

class MacReq(BaseModel):
    key_lmk: str
    ksn: Optional[str] = None
    mac_mode: MacMode
    msg: str
    mac: Optional[str] = None

class MacResp(BaseModel):
    status: str
    mac_resp: Optional[str] = None
    class Config:
        from_attributes = True


class TransPinReq(BaseModel):
    key_lmk: str
    ksn: Optional[str] = None
    src_pinblk: str
    dest_key: str
    dest_ksn: Optional[str] = None
    pan: str

class TransPinResp(BaseModel):
    status: str
    dest_pinblk: Optional[str] = None
    class Config:
        from_attributes = True


class ExpTr31Req(BaseModel):
    key_lmk: str
    zmk_lmk: str
    iksn: Optional[str] = None

class ExpTr31Resp(BaseModel):
    status: str
    key_zmk: Optional[str] = None
    class Config:
        from_attributes = True


class WrapReq(BaseModel):
    algo: Algo
    header: Optional[str] = None
    kbpk: str
    key: str

class WrapResp(BaseModel):
    key_kbpk: str
    status: str
    class Config:
        from_attributes = True

class UnwrapReq(BaseModel):
    key_kbpk: str
    kbpk: str

class UnwrapResp(BaseModel):
    key: str
    status: str
    class Config:
        from_attributes = True
