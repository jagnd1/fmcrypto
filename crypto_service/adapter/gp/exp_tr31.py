from typing import Tuple

from common.utils.enum.algo import Algo
from common.utils.gp.sym_key import SymKey
from common.utils.sw.tr31 import Tr31
from crypto_service.domain.models.exp_tr31 import ExpTr31 as BaseExpTr31

class ExpTr31(BaseExpTr31):
    
    def __init__(self):
        super().__init__()
        print("gp exp key: ")
        self.tr31_obj = Tr31()
    
    def _extract_header(self, key_lmk: str):
        _header = key_lmk[:1] + key_lmk[5:12]
        return _header
    
    def build(self, exp_key: bytes, key: bytes, _: bytes) -> bytes:
        sym_key_obj = SymKey()
        algo: Algo = Algo.A128  # T O D O: make this parameter
        exp_key_clear = sym_key_obj.get_key_val(algo, exp_key)
        key_clear = sym_key_obj.get_key_val(algo, key)
        header = self._extract_header(key.decode())
        self.tr31_blob = self.tr31_obj.wrap(exp_key_clear, key_clear, header)
        return self.tr31_blob.encode()

    def parse(self, resp: bytes) -> None:
        """dummy for gp hsm"""
        pass

    def get_key(self) -> Tuple[bytes, bytes]:
        return self.tr31_blob.encode(), b''
