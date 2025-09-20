from typing import Tuple
from common.utils.enum.algo import Algo
from common.utils.gp.asym_key import AsymKey
from crypto_service.app.utils.enum.use_mode import UseMode
from crypto_service.domain.models.kp_gen import KpGen as BaseKpGen

class KpGen(BaseKpGen):
    
    def __init__(self):
        super().__init__()
        print("gp kp gen: ")
        self.asym_key_obj = AsymKey()

    def build(self, in_algo: Algo, in_use_mode: UseMode) -> bytes:
        self.pk, self.sk = self.asym_key_obj.gen_kp(in_algo)

    def parse(self, resp: bytes):
        """ dummy for gp hsm """
        pass

    def get_kp(self) -> Tuple[bytes, bytes]:
        return self.pk, self.sk
