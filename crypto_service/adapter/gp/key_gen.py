from typing import Tuple

from common.utils.enum.algo import Algo
from common.utils.gp.sym_key import SymKey
from crypto_service.app.utils.enum.key_type import KeyType
from crypto_service.app.utils.enum.use_mode import UseMode
from crypto_service.domain.models.key_gen import KeyGen as BaseKeyGen

class KeyGen(BaseKeyGen):
    
    def __init__(self):
        print("gp key gen: ")
        self.sym_key_obj = SymKey()

    def build(
        self, in_key_type: KeyType, in_use_mode: UseMode, in_exp_key: bytes, 
        in_algo: Algo) -> bytes:
        # key_type, use_mode and exp_key not used
        self.key_lmk = self.sym_key_obj.gen_key(in_algo)
        self.kcv = self.sym_key_obj.get_kcv(in_algo, self.key_lmk)
        return self.key_lmk

    def parse(self, resp: bytes):
        """dummy for gp hsm"""
        pass

    def get_key(self) -> Tuple[bytes, bytes]:
        return self.key_lmk, self.kcv
