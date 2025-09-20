from typing import Any
from common.utils.enum.algo import Algo
from common.utils.gp.asym_key import AsymKey
from common.utils.gp.sym_key import SymKey
from crypto_service.app.utils.enum.key_type import KeyType
from crypto_service.app.utils.enum.use_mode import UseMode
from crypto_service.domain.models.ecdh import Ecdh as BaseEcdh

class Ecdh(BaseEcdh):
    
    def __init__(self):
        super().__init__()
        print("gp ecdh: ")
        self.asym_key_obj = AsymKey()
        self.recv_pk, self.recv_sk = self.asym_key_obj.gen_kp(Algo.ECP256)
        self.kcv = b""
        self.shared_info = b""
        self.shs = b""

    def build_recp_derive_shared(
        self, in_algo: Algo, init_pk: bytes, shared_info: bytes, key_type: KeyType, 
        in_use_mode: UseMode) -> bytes:
        # shared info, key type and use mode not used
        self.derived_key_lmk, self.recv_pk = self.asym_key_obj.ecdh(
            in_algo, self.recv_sk, self.recv_pk, init_pk)
        if self.recv_pk:
            sym_key_obj = SymKey()
            self.kcv = sym_key_obj.get_kcv(Algo.A128, self.derived_key_lmk)
            return self.recv_pk

    def parse_recp_derive_shared(self, resp: bytes):
        """dummy for gp hsm"""
        pass

    def get_recp_derive(self) -> Any:
        return self.derived_key_lmk, self.kcv, self.recv_pk


