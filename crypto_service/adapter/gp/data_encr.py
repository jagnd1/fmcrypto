from common.utils.enum.algo import Algo
from common.utils.enum.encr_mode import EncrMode
from common.utils.gp.sym_key import SymKey
from crypto_service.domain.models.data_encr import DataEncr as BaseDataEncr

class DataEncr(BaseDataEncr):
    
    def __init__(self):
        super().__init__()
        print("gp data encr: ")
        self.sym_key_obj = SymKey()

    def build(
        self, msg: bytes, key: bytes, encr_mode: EncrMode, iv: str, ksn: bytes, 
        algo: Algo) -> bytes:
        # T O D O: encr mode - check default is CBC or not
        # T O D O: determine key type and len 
        # ksn is not used, as no support for DUKPT on pkcs11
        self.encr_data = self.sym_key_obj.encrypt(algo, EncrMode.CBC_PAD, key, iv.encode(), msg)
        return self.encr_data

    def parse(self, resp: bytes):
        """dummy for gp hsm"""
        pass

    def get_msg(self) -> bytes:
        return self.encr_data
