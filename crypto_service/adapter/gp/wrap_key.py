
from common.utils.enum.algo import Algo
from common.utils.sw.tr31 import Tr31
from crypto_service.domain.models.wrap_key import WrapKey as BaseWrapKey

class WrapKey(BaseWrapKey):

    def __init__(self):
        print("gp wrap key: ")
        self.tr31_obj = Tr31()

    def build(self, algo: Algo, header: str, kbpk: bytes, key: bytes):
        if algo in [Algo.R2K, Algo.R3K, Algo.R4K, Algo.ECP256, Algo.ECP384, Algo.ECP521]:
            _header = self.tr31_obj.asym_header
        else:
            _header = self.tr31_obj.sym_header
        self.key_kbpk = self.tr31_obj.wrap(kbpk, key, _header)
        print(f"key_kbpk: {self.key_kbpk}")

    def parse(self, resp: str):
        """ dummy for gp hsm """
        pass

    def get_key(self) -> str:
        return self.key_kbpk
