from common.utils.enum.algo import Algo
from common.utils.gp.asym_key import AsymKey
from crypto_service.domain.models.gen_sign import GenSign as BaseGenSign

class GenSign(BaseGenSign):
    
    def __init__(self):
        super().__init__()
        print("gp gen sign: ")
        self.asym_key_obj = AsymKey()


    def build(self, in_sign_algo: Algo, msg: bytes, sk_lmk: bytes) -> bytes:
        self.sign_data = self.asym_key_obj.sign(in_sign_algo, sk_lmk, msg)
        return self.sign_data

    def parse(self, resp: bytes):
        """dummy for gp hsm"""
        pass
    
    def get_sign_data(self) -> bytes:
        return self.sign_data
