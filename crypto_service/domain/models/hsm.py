from abc import ABC, abstractmethod
from typing import Any

from common.utils.enum.algo import Algo
from crypto_service.domain.models.client import Client
from crypto_service.domain.models.data_decr import DataDecr
from crypto_service.domain.models.data_encr import DataEncr
from crypto_service.domain.models.ecdh import Ecdh
from crypto_service.domain.models.exp_key import ExpKey
from crypto_service.domain.models.exp_tr31 import ExpTr31
from crypto_service.domain.models.exp_tr34 import ExpTr34
from crypto_service.domain.models.gen_sign import GenSign
from crypto_service.domain.models.ipek_derive import IpekDerive
from crypto_service.domain.models.kcv_gen import KcvGen
from crypto_service.domain.models.key_gen import KeyGen
from crypto_service.domain.models.mac_impl import MacImpl
from crypto_service.domain.models.pk_imp import PkImp
from crypto_service.domain.models.rand_gen import RandGen
from crypto_service.domain.models.trans_pin import TransPin
from crypto_service.domain.models.unwrap_key import UnwrapKey
from crypto_service.domain.models.wrap_key import WrapKey

class HSM(ABC):
    
    def __init__(self):
        print("abs hsm method")

    @abstractmethod
    def get_gen_sign(self) -> GenSign:
        pass
    @abstractmethod
    def get_kp_gen(self, algo: Algo) -> Any:
        pass
    @abstractmethod
    def get_ecka_dh(self) -> Ecdh:
        pass
    @abstractmethod
    def get_exp_key(self) -> ExpKey:
        pass
    @abstractmethod
    def get_exp_tr31(self) -> ExpTr31:
        pass
    @abstractmethod
    def get_pk_imp(self) -> PkImp:
        pass
    @abstractmethod
    def get_exp_tr34(self) -> ExpTr34:
        pass
    @abstractmethod
    def get_rand_gen(self) -> RandGen:
        pass
    @abstractmethod
    def get_key_gen(self) -> KeyGen:
        pass
    @abstractmethod
    def get_ipek_derive(self) -> IpekDerive:
        pass
    @abstractmethod
    def get_data_decr(self) -> DataDecr:
        pass
    @abstractmethod
    def get_data_encr(self) -> DataEncr:
        pass
    @abstractmethod
    def get_mac(self) -> MacImpl:
        pass
    @abstractmethod
    def get_trans_pin(self) -> TransPin:
        pass
    @abstractmethod
    def get_kcv_gen(self) -> KcvGen:
        pass
    @abstractmethod
    def get_wrap_key(self) -> WrapKey:
        pass
    @abstractmethod
    def get_unwrap_key(self) -> UnwrapKey:
        pass
    @abstractmethod
    def get_client(self) -> Client:
        pass
    @abstractmethod
    async def close_client(self):
        pass
    @abstractmethod
    async def check_client(self, interval:int=300):
        pass
    
