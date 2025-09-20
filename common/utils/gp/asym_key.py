import functools
from typing import Tuple
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

from common.utils.enum.algo import Algo
from common.utils.gp.sym_key import SymKey
from common.utils.crypto import Utils as NewUtils

class AsymKey(SymKey):

    def __init__(self):
        super().__init__()
    
    def _get_key_len(self, algo: Algo) -> str:
        if algo is Algo.R2K:
            oid_len = '2048'
        elif algo is Algo.R3K:
            oid_len = '3072'
        elif algo is Algo.R4K:
            oid_len = '4096'
        elif algo is Algo.ECP256:
            oid_len = 'secp256r1'
        elif algo is Algo.ECP384:
            oid_len = 'secp384r1'
        elif algo is Algo.ECP521:
            oid_len = 'secp521r1'
        else:
            raise ValueError("invalid key type!")
        return oid_len

    def gen_kp(self, algo: Algo) -> Tuple[bytes, bytes]:
        pk, sk = NewUtils.gen_key(algo)
        pk_der = NewUtils.serialize_pk(pk)
        print(f"pk_der: {pk_der.hex()}")
        sk_der = NewUtils.serialize_sk(sk_obj=sk, format='DER', algo=algo)
        # print(f"sk_der: {sk_der.hex()}")
        sk_lmk = self._wrap_key(algo, sk_der)
        print(f"sk lmk: {sk_lmk.hex()}")
        return pk_der, sk_lmk
    
    def asym_encrypt(self, algo: Algo, pk: bytes, data: bytes) -> bytes:
        if algo in [Algo.ECP256, Algo.ECP384, Algo.ECP521]:
            raise TypeError("no encr using EC keys!")
        else:
            pk_obj = NewUtils.deserialize_pk(pk)
            return NewUtils.pk_encrypt(data, pk_obj)
    
    def asym_decrypt(self, algo: Algo, sk_lmk: bytes, data: bytes) -> bytes:
        if algo in [Algo.ECP256, Algo.ECP384, Algo.ECP521]:
            raise TypeError("no encr using EC keys!")
        else:
            sk = self._unwrap_key(algo, sk_lmk)
            sk_obj = NewUtils.deserialize_sk(sk)
            return NewUtils.sk_decrypt(data, sk_obj)
    
    def sign(self, algo: Algo, sk_lmk: bytes, data: bytes) -> bytes:
        sk = self._unwrap_key(algo, sk_lmk)
        sk_obj = NewUtils.deserialize_sk(sk)
        return NewUtils.sign(data, sk_obj, algo)
    
    def verify(self, algo: Algo, pk: bytes, data: bytes, signature: bytes) -> bool:
        pk_obj = NewUtils.deserialize_pk(pk)
        return NewUtils.verify(data, pk_obj, algo, signature)

    def exp_key(self, _: Algo, pk: bytes, sym_algo: Algo, 
                key_lmk: bytes) -> bytes:
        # unwrap from lmk
        _key = self._unwrap_key(sym_algo, key_lmk)
        # convert pk to pk obj
        pk_obj = NewUtils.deserialize_pk(pk)
        # encrypt the unwrapped key under pk
        return NewUtils.pk_encrypt(_key, pk_obj)

    def imp_key(self, asym_algo: Algo, sk_lmk: bytes, sym_algo: Algo, 
                key_pk: bytes) -> bytes:
        # unwrap sk from lmk
        _sk = self._unwrap_key(asym_algo, sk_lmk)
        # convert sk to sk obj
        _sk_obj = NewUtils.deserialize_sk(_sk)
        # decrypt the encrypted sym key
        _key = NewUtils.sk_decrypt(key_pk, _sk_obj)
        # print(f"clear key: {_key.hex()}")
        # wrap the decrypted sym key under lmk
        return self._wrap_key(sym_algo, _key)

    def ecdh(self, algo: Algo, recv_sk: bytes, recv_pk: bytes, 
             init_pk: bytes) -> Tuple[bytes, bytes]:
        # for ECDHE, expect recv key pair is generated fresh for every operation 
        # verify the algo
        if algo in [Algo.R2K, Algo.R3K, Algo.R4K]:
            raise TypeError("invalid key algo! RSA not supported for ECDH")
        # unwrap recv sk from lmk
        _recv_sk = self._unwrap_key(algo, recv_sk)
        # convert the sk in sk obj
        _recv_sk_obj = NewUtils.deserialize_sk(_recv_sk)
        # convert pk into pk obj
        _init_pk_obj = NewUtils.deserialize_pk(init_pk)

        # derivation
        # T O D O: get the key to be derived len as arg
        sym_algo = Algo.A128
        _key_len = int(super()._get_key_len(sym_algo)/8)
        kdf = functools.partial(HKDF, key_len=_key_len, salt=None, hashmod=SHA256, 
                                num_keys=1, context=b'ANSI X9.63 KDF Context')
        _derived_key = key_agreement(eph_priv=_recv_sk_obj, eph_pub=_init_pk_obj, kdf=kdf)
        print(f"clear derived key: {_derived_key.hex()}")
        # trust the recv pk (import under lmk)!
        # recv_pk_lmk = self._wrap_key(algo, recv_pk)
        return self._wrap_key(sym_algo, _derived_key), recv_pk
