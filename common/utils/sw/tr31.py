import psec

from common.utils.crypto import Utils

default_sym_header =  "DD0AB00E"
default_sym_tdes_header = "DP0TE00N"
ipek = "DB1AX00E"
default_asym_header =   "DS0ES00E"

class Tr31:
    def __init__(self):
        # print("tr31 using psec")
        self.sym_header = default_sym_header
        self.asym_header = default_asym_header
        self.sym_tdes_header = default_sym_tdes_header

    def wrap(self, kbpk: bytes, key: bytes, header: str = default_sym_header) -> str:
        _header = psec.tr31.Header(
            version_id = header[0],
            key_usage = header[1:3],
            algorithm = header[3],
            mode_of_use = header[4],
            version_num = header[5:7],
            exportability = header[7]
        )
        kb = psec.tr31.KeyBlock(kbpk=kbpk, header=_header)
        tr31_blob = kb.wrap(key=key, masked_key_len=0)
        return tr31_blob

    def unwrap(self, kbpk: bytes, tr31_blob: str) -> bytes:
        _, key = psec.tr31.unwrap(kbpk=kbpk, key_block=tr31_blob)
        # print(f"unwrapped key: {key}")
        return key


