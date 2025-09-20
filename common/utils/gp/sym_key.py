import os

from common.utils.enum.algo import Algo
from common.utils.enum.encr_mode import EncrMode
from common.utils.sw.tr31 import Tr31
from common.utils.crypto import Utils as NewUtils

class SymKey():

    def __init__(self):
        self.tr31_obj = Tr31()
        self.lmk = NewUtils.hash(Algo.ECP256, "lmk".encode())

    def _get_lmk(self):
        print(f"lmk: {self.lmk.hex()}")
        return self.lmk 
    
    def _get_key_len(self, in_algo: Algo):
        if in_algo in [Algo.A128, Algo.A192, Algo.A256, Algo.TDES]:
            lenlen = 128
            if in_algo is Algo.A192:
                lenlen = 192
            elif in_algo is Algo.A256:
                lenlen = 256
        else:
            raise ValueError("wrong algo passed!")
        return lenlen

    def _wrap_key(self, algo: Algo, key: bytes, header=None) -> str:
        _key = key
        if not header:
            if algo in [Algo.R2K, Algo.R3K, Algo.R4K, Algo.ECP256, Algo.ECP384, Algo.ECP521]:
                _header = self.tr31_obj.asym_header
            else:
                if algo in [Algo.A128, Algo.A192, Algo.A256]:
                    _header = self.tr31_obj.sym_header
                else:
                    _header = self.tr31_obj.sym_tdes_header
        else:
            _header = header
        tr31_blob = self.tr31_obj.wrap(self.lmk, _key, _header)
        print(f"wrapped key: {tr31_blob}")
        return tr31_blob.encode()

    def _unwrap_key(self, _: Algo, key_lmk: bytes) -> bytes:
        _tr31_blob = key_lmk.decode()
        _key = self.tr31_obj.unwrap(self.lmk, _tr31_blob)
        print(f"unwrapped key: {_key.hex()}")
        return _key
    
    def gen_key(self, in_algo: Algo) -> bytes:
        # return key encrypted under lmk
        _key = os.urandom(int(self._get_key_len(in_algo)/8))
        print(f"clear key: {_key.hex()}")
        return self._wrap_key(in_algo, _key)
    
    def _get_key(self, algo: Algo, key_lmk: bytes) -> bytes:
        return self._unwrap_key(algo, key_lmk)
    
    def get_key_val(self, algo: Algo, key_lmk: bytes) -> bytes:
        return self._unwrap_key(algo, key_lmk)
    
    def set_key_val(self, algo: Algo, key: bytes, header=None) -> bytes:
        return self._wrap_key(algo, key, header)
    
    def encrypt(self, algo: Algo, encr_mode: EncrMode, key: bytes, iv: bytes, data: bytes) -> bytes:
        _key = self._unwrap_key(algo, key)
        key_block_size = 8
        if algo in [Algo.A128, Algo.A192, Algo.A256]:
            key_block_size = 16
        padded_data = NewUtils._pad(data, key_block_size)
        encr_data, _ =  NewUtils.encrypt(encr_mode, algo, padded_data, _key, iv)
        return encr_data
    
    def decrypt(self, algo: Algo, encr_mode: EncrMode, key: bytes, iv: bytes, data: bytes) -> bytes: 
        _key = self._unwrap_key(algo, key)
        decr_data =  NewUtils.decrypt(encr_mode, algo, data, _key, iv)
        key_block_size = 8
        if algo in [Algo.A128, Algo.A192, Algo.A256]:
            key_block_size = 16
        if len(decr_data) != key_block_size:
            data = NewUtils._unpad(decr_data, key_block_size)
        else:
            data = decr_data
        return data
    
    def sign(self, algo: Algo, key: bytes, data: bytes) -> bytes:
        _key = self._unwrap_key(algo, key)
        return NewUtils.sym_sign(algo=algo, key=_key, data=data)
    
    def get_kcv(self, algo: Algo, key: bytes) -> bytes:
        kcv = b''
        if algo in [Algo.A128, Algo.A192, Algo.A256]:
            kcv =  self.sign(algo, key, bytes(16))[:3]
        else:
            # T O D O: kcv for TDES
            # kcv = self.encrypt(algo, EncrMode.ECB, key, bytes(8), bytes(16))[:3]
            pass
        return kcv
    
    def generate_random(self, len) -> bytes:
        return os.urandom(len)
    
    def close(self):
        # nothing to be done here for sw impl
        pass

