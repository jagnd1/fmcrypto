from common.utils.enum.algo import Algo
from common.utils.gp.sym_key import SymKey
from crypto_service.domain.models.kcv_gen import KcvGen as BaseKcvGen

class KcvGen(BaseKcvGen):
    
    def __init__(self):
        print("gp kcv gen: ")
        self.sym_key_obj = SymKey()
        self.kcv = b""

    def build(self, in_key: bytes) -> bytes:
        # T O D O: determin the algo from the key
        # T O D O: implement for TDES
        self.kcv = self.sym_key_obj.get_kcv(Algo.A128, in_key)
        return self.kcv

    def parse(self, resp: bytes):
        """dummy for gp hsm"""
        pass

    def get_kcv(self) -> bytes:
        return self.kcv