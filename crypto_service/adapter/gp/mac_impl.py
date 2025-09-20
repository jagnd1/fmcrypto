
from common.utils.enum.algo import Algo
from common.utils.gp.sym_key import SymKey
from crypto_service.app.utils.enum.mac_mode import MacMode
from crypto_service.domain.models.mac_impl import MacImpl as BaseMac

class MacImpl(BaseMac):
    
    def __init__(self):
        super().__init__()
        print("gp mac impl: ")
        self.sym_key_obj = SymKey()

    def build(self, key: bytes, ksn: bytes, in_mac_mode: MacMode, mac: bytes, msg: bytes) -> bytes:
        # T O D O: DUKPT support - ksn not used, TDES support
        # T O D O: MAC verify - in_mac_mode not used
        # T O D O: determine key type and len based on algo and make it dynamic parameter
        self.mac = self.sym_key_obj.sign(Algo.A128, key, msg)[:3]
        return self.mac

    def parse(self, resp: bytes):
        """ dummy for gp hsm """
        pass

    def get_mac(self) -> bytes:
        return self.mac
