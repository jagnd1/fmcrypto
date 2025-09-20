from typing import Tuple

from common.utils.enum.algo import Algo
from common.utils.gp.sym_key import SymKey
from common.utils.sw.dukpt import Dukpt, KeyType
from crypto_service.app.utils.enum.use_mode import UseMode
from crypto_service.domain.models.ipek_derive import IpekDerive as BaseIpekDerive

class IpekDerive(BaseIpekDerive):
    """ disable ipek derive for gp - this is enabled for demo and implemented using sw  key mgmt"""
    def __init__(self):
        print("gp ipek derive: ")
        self.sym_key_obj = SymKey()

    def build(
        self, bdk: bytes, iksn: bytes, tk: bytes, in_algo: Algo, in_use_mode: UseMode) -> bytes:
        bdk_clear = self.sym_key_obj.get_key_val(in_algo, bdk)
        dukpt_obj = Dukpt()
        if in_algo is Algo.A128:
            key_type = KeyType._AES128 
        elif in_algo is Algo.A192:
            key_type = KeyType._AES192
        elif in_algo is Algo.A256:
            key_type = KeyType._AES256
        else:
            raise ValueError("invalid algo!")
        init_key_id = iksn[:8]
        ipek_clear = dukpt_obj.derive_initial_key(bdk_clear, key_type, init_key_id)
        print(f"ipek clear: {ipek_clear.hex()}")
        ipek_header = "DB1AX00E"
        self.ipek_lmk = self.sym_key_obj.set_key_val(in_algo, ipek_clear, ipek_header)
        print(f"ipek lmk: {self.ipek_lmk.hex()}")
        self.kcv = self.sym_key_obj.get_kcv(in_algo, self.ipek_lmk)
        return b""

    def parse(self, resp: bytes):
        """dummy for gp hsm"""
        pass

    def get_key(self) -> Tuple[bytes, bytes, bytes]:
        return self.ipek_lmk, b"", self.kcv
