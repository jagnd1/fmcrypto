from enum import Enum
from pydantic import BaseModel

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
    IPEK = "IPEK"

class Address(BaseModel):
    line1: str
    line2: str
    city: str
    state: str
    zipcode: str
    country: str

class UserBase(BaseModel):
    user_id: str = ""
    user_name: str
    email: str
    first_name: str
    last_name: str
    contact: str
    address: Address

class UserCreate(UserBase):
    password: str