from typing import Tuple
from common.utils.enum.algo import Algo
from common.utils.gp.tr34 import Tr34
from crypto_service.domain.models.exp_tr34 import ExpTr34 as BaseExpTr34

class ExpTr34(BaseExpTr34):
    
    def __init__(self):
        super().__init__()
        print("gp exp tr34: ")
        self.tr34_obj = Tr34()

    def build(
        self, kbpk: bytes, kcv: bytes, kdh_cert: bytes, krd_cert: bytes, kdh_sk: bytes) -> bytes:
        sym_key_algo = Algo.A128
        kbpk_clear = self.tr34_obj.sym_key_obj.get_key_val(sym_key_algo, kbpk)
        ed_obj = self.tr34_obj.build_ed(krd_cert, kbpk_clear, sym_key_algo)
        self.tr34_obj.sym_key_obj.close()   # T O D O: keep the session open between multiples logins
        self.sd = self.tr34_obj.build_sd("sha256", ed_obj, kdh_cert, kdh_sk)

    def parse(self, resp: bytes):
        """dummy for gp hsm"""
        pass

    def get_tr34(self) -> Tuple[bytes, bytes, bytes]:
        return b"", self.sd, b""
