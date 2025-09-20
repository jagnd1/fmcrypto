import psec
import psec.pinblock
from common.utils.enum.algo import Algo
from common.utils.enum.encr_mode import EncrMode
from common.utils.gp.sym_key import SymKey
from common.utils.sw.dukpt import Dukpt, KeyType, KeyUsage
from crypto_service.domain.models.trans_pin import TransPin as BaseTransPin
from common.utils.crypto import Utils as NewUtils

class TransPin(BaseTransPin):
    
    def __init__(self):
        super().__init__()
        print("gp trans pin: ")
        self.dukpt_obj = Dukpt()
        self.sym_key_obj = SymKey()
        self.encr_pin_blk = b''

    def _get_pan_field(self, pan: bytes) -> bytes:
        pan_field = "4" + pan.hex()
        zero_pad = '0'* (32-len(pan_field))
        pan_field = pan_field + zero_pad
        return bytes.fromhex(pan_field)

    def build(
        self, key: bytes, dest_key: bytes, ksn: bytes, src_pinblk: bytes, pan: bytes, 
        _: bytes = None) -> bytes:
        _pan = bytes.fromhex(pan.decode())
        # 1. decrypt the ipek_lmk
        print(f"ipek_lmk: {key.hex()}")
        ipek_clear = self.sym_key_obj.get_key_val(Algo.A128, key)
        print(f"ipek clear: {ipek_clear.hex()}")
        # 1.1. extract intitial key id and counter from ksn
        initial_key_id = ksn[:8]
        print(f"initial key id: {initial_key_id.hex()}")
        counter = int(ksn[9:].hex())
        print(f"counter: {ksn[9:].hex()}")
        # 1.2. derive working key from ipek and initial key id and counter
        _, _, wk_clear = self.dukpt_obj.derive_working_key(
            ipek_clear, KeyType._AES128, KeyUsage._PINEncryption, KeyType._AES128, initial_key_id, 
            counter)
        print(f"working key: {wk_clear.hex()}")
        # 2. decrypt the source pin block
        wk_lmk = self.sym_key_obj.set_key_val(Algo.A128, wk_clear)
        print(f"working key under lmk: {wk_lmk.hex()}")
        block_b = self.sym_key_obj.decrypt(Algo.A128, EncrMode.ECB, wk_lmk, b"", src_pinblk)
        print(f"block b: {block_b.hex()}")
        pan_field = self._get_pan_field(_pan)
        print(f"pan field: {pan_field.hex()}")
        block_a = NewUtils.xor(block_b, pan_field)
        print(f"block a: {block_a.hex()}")
        pin_field = self.sym_key_obj.decrypt(Algo.A128, EncrMode.ECB, wk_lmk, b"", block_a)
        print(f"pin field: {pin_field.hex()}")
        # 3. extract the pin
        pin_len = int(pin_field.hex()[1], 16)
        print(f"lenlen: {pin_len}")
        pin_clear = pin_field.hex()[2:pin_len+2]
        print(f"pin clear: {pin_clear}")
        # 4. encode pin in iso 0 (or ansi x9.8) format
        pin_blk_clear = psec.pinblock.encode_pinblock_iso_0(pin_clear, _pan.hex())
        print(f"pin blk clear: {pin_blk_clear.hex()}")
        # 5. encrypt under the dest key
        iv = bytes(8)
        self.encr_pin_blk = self.sym_key_obj.encrypt(
            Algo.TDES, EncrMode.ECB, dest_key, iv, pin_blk_clear)
        print(f"encr pin blk: {self.encr_pin_blk.hex()}")
        return self.encr_pin_blk

    def parse(self, resp: bytes):
        """dummy for gp hsm"""
        pass

    def get_pinblk(self) -> bytes:
        return self.encr_pin_blk.hex().encode()



