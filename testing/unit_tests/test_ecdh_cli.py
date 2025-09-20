from enum import Enum, auto
import functools
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

from common.utils.crypto import Utils
from common.utils.enum.algo import Algo

class KDFMETHOD(Enum):
    X963=auto()
    SP800_56C=auto()

kdf_method: KDFMETHOD = KDFMETHOD.X963

def kp_gen(curve='P-256'):
    private_key = ECC.generate(curve=curve)
    public_key = private_key.public_key()
    return private_key, public_key

def prepare_kdf(shared_secret, length=16, salt=None, counter_start=1):
    fixed_info = b''
    if kdf_method == KDFMETHOD.X963:
        print("using kdf = X9.63")
        # X9.63 KDF: Hash(Z || counter || Fixed Info)
        # Z = shared_secret, counter = 4-byte integer, Fixed Info = fixed information
        kdf_input = shared_secret + (counter_start).to_bytes(4, byteorder='big') + fixed_info
    elif  kdf_method == KDFMETHOD.SP800_56C:
        print("using kdf = SP800 56C")
        # SP800-56C KDF: Hash(counter || Z || Fixed Info)
        # counter = 4-byte integer, Z = shared_secret, Fixed Info = fixed information
        kdf_input = (counter_start).to_bytes(4, byteorder='big') + shared_secret + fixed_info
    else:
        raise ValueError("invalid kdf method!")
    derived_key = SHA256.new(kdf_input).digest()
    return derived_key[:length]

    
def get_kcv(algo: Algo, key: bytes) -> bytes:
        kcv = b''
        if algo in [Algo.A128, Algo.A192, Algo.A256]:
            kcv =  Utils.sym_sign(algo, key, bytes(16))[:3]
        else:
            raise ValueError("invalid algo!")
        return kcv

def ecdh_cli():
    # use fixed keys for tes purpose
    pos_pk_der = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004e79c5744a6b1df7b955416a735e044a64ab14cfc00796c673f3f93563c07c87fe3aee5ad21d3741ef21a73d8b5a3a510007e7c5650cf0c31708832aad9f7da7b")
    pos_sk_der = bytes.fromhex("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420fde210b35c15e20b51a8eb1e31a90ca28eea9d798e8c0f867799ba985e1f0b36a14403420004e79c5744a6b1df7b955416a735e044a64ab14cfc00796c673f3f93563c07c87fe3aee5ad21d3741ef21a73d8b5a3a510007e7c5650cf0c31708832aad9f7da7b")
    pos_sk_obj = Utils.deserialize_sk(pos_sk_der)
    be_pk_der  = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200043b17d48f622d3739379012e8bc20e284763136cc22505c5f81bab5a38ae74752dc8025ba7ab5890cbce1d4a562e46e7a30efabbe124a01ade0a406bb7accd0e6")
    be_pk_obj = Utils.deserialize_pk(be_pk_der)
    # prepare kdf cb
    kdf_ret = functools.partial(prepare_kdf, length=16, salt=None)
    # call the ecdh
    derived_key = key_agreement(eph_priv=pos_sk_obj, eph_pub=be_pk_obj, kdf=kdf_ret)
    print(f"derived key: {derived_key.hex()}")
    kcv = get_kcv(Algo.A128, derived_key)
    print(f"kcv: {kcv.hex()}")
    print(f"pos pk b64u: {Utils.urlsafe_b64encode(pos_pk_der)}")


# Running the example
if __name__ == "__main__":
    ecdh_cli()
