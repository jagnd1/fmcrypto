from crypto_service.adapter.gp.kcv_gen import KcvGen
from crypto_service.domain.models.hsm import HSM as BaseHSM
from common.utils.enum.algo import Algo
from crypto_service.adapter.gp.data_decr import DataDecr
from crypto_service.adapter.gp.data_encr import DataEncr
from crypto_service.adapter.gp.ecdh import Ecdh
from crypto_service.adapter.gp.exp_key import ExpKey
from crypto_service.adapter.gp.exp_tr31 import ExpTr31
from crypto_service.adapter.gp.exp_tr34 import ExpTr34
from crypto_service.adapter.gp.gen_sign import GenSign
from crypto_service.adapter.gp.gp_client import GPClient
from crypto_service.adapter.gp.ipek_derive import IpekDerive
from crypto_service.adapter.gp.key_gen import KeyGen
from crypto_service.adapter.gp.kp_gen import KpGen
from crypto_service.adapter.gp.mac_impl import MacImpl
from crypto_service.adapter.gp.rand_gen import RandGen
from crypto_service.adapter.gp.trans_pin import TransPin
from crypto_service.adapter.gp.wrap_key import WrapKey
from crypto_service.adapter.gp.unwrap_key import UnwrapKey

ERR_NO_IMPL = "not implemented in GP"

gp_client = GPClient()

class GPHSM(BaseHSM):
        
    def get_gen_sign(self) -> GenSign:
        return GenSign()
    def get_kp_gen(self, algo: Algo) -> KpGen:
        return KpGen()
    def get_ecka_dh(self) -> Ecdh:
        return Ecdh()
    def get_exp_key(self) -> ExpKey:
        return ExpKey()
    def get_exp_tr31(self) -> ExpTr31:
        return ExpTr31()
    def get_pk_imp(self) -> None:
        raise NotImplementedError(ERR_NO_IMPL)
    def get_exp_tr34(self) -> ExpTr34:
        return ExpTr34()
    def get_rand_gen(self) -> RandGen:
        return RandGen()
    def get_key_gen(self) -> KeyGen:
        return KeyGen()
    def get_ipek_derive(self) -> IpekDerive:
        return IpekDerive()
    def get_data_decr(self) -> DataDecr:
        return DataDecr()
    def get_data_encr(self) -> DataEncr:
        return DataEncr()
    def get_mac(self) -> MacImpl:
        return MacImpl()
    def get_trans_pin(self) -> TransPin:
        return TransPin()
    def get_kcv_gen(self) -> KcvGen:
        return KcvGen()
    def get_wrap_key(self) -> WrapKey:
        return WrapKey()
    def get_unwrap_key(self) -> UnwrapKey:
        return UnwrapKey()
    def get_client(self) -> GPClient:
        return gp_client
    async def close_client(self):
        await gp_client.close()
    async def check_client(self, interval: int=300):
        await gp_client.check(interval)
