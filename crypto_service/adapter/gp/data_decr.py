from common.utils.enum.algo import Algo
from common.utils.enum.encr_mode import EncrMode
from common.utils.gp.sym_key import SymKey
from crypto_service.domain.models.data_decr import DataDecr as BaseDataDecr

class DataDecr(BaseDataDecr):
    
    def __init__(self):
        super().__init__()
        print("gp data decr: ")
        self.sym_key_obj = SymKey()

    def build(
        self, key: bytes, iv: str, enc_msg: bytes, encr_mode: EncrMode = EncrMode.CBC_PAD, 
        ksn: bytes = b'', algo: Algo = Algo.A128) -> bytes:
        self.decr_msg = self.sym_key_obj.decrypt(algo, EncrMode.CBC_PAD, key, iv.encode(), enc_msg)
        return  self.decr_msg

    def parse(self, resp: bytes):
        """dummy for gp hsm"""
        pass

    def get_msg(self) -> bytes:
        return self.decr_msg
