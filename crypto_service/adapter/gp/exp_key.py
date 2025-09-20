from typing import Tuple
from common.utils.enum.algo import Algo
from common.utils.gp.asym_key import AsymKey
from crypto_service.domain.models.exp_key import ExpKey as BaseExpKey

class ExpKey(BaseExpKey):
    
    def __init__(self):
        super().__init__()
        print("gp exp key: ")
        self.asym_key_obj = AsymKey()

    def build(self, key: bytes, kcv: bytes, pk: bytes) -> bytes:
        # T O D O: 1. no way to prevent usage of EC keys, no Encr or Wrapping support for EC keys, 
        # only RSA so dynamically determine key len for RSA
        # 2. kcv not used
        # 3. sym key considered as A128, make this dynamic
        self.key_pk = self.asym_key_obj.exp_key(Algo.R2K, pk, Algo.A128, key)
        return self.key_pk

    def parse(self, resp: bytes):
        """dummy for gp hsm"""
        pass

    def get_enc_key(self) -> Tuple[bytes, bytes]:
        return self.key_pk, b""
