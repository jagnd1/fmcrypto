
from common.utils.sw.tr31 import Tr31
from crypto_service.domain.models.unwrap_key import UnwrapKey as BaseUnwrapKey

class UnwrapKey(BaseUnwrapKey):
    
    def __init__(self):
        print("gp unwrap key: ")
        self.tr31_obj = Tr31()

    def build(self, kbpk: bytes, key: str):
        self.key = self.tr31_obj.unwrap(kbpk, key)
        print(f"unwrapped key: {self.key.decode()}")

    def parse(self, resp: str):
        """ dummy for gp hsm """
        pass

    def get_key(self) -> str:
        return self.key
