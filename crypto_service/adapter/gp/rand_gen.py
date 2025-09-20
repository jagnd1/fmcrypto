from common.utils.gp.sym_key import SymKey
from crypto_service.domain.models.rand_gen import RandGen as BaseRandGen

class RandGen(BaseRandGen):
    
    def __init__(self):
        super().__init__()
        print("gp rand gen: ")
        self.key_obj = SymKey()

    def build(self, in_len: int) -> bytes:
        self.rand_no = self.key_obj.generate_random(in_len)
        return self.rand_no

    def parse(self, resp: bytes) -> None:
        """ dummy in gp hsm """
        pass

    def get_random_no(self) -> bytes:
        return self.rand_no
