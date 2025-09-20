from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Union
from asn1crypto import x509, csr, crl, keys
from Crypto.PublicKey import ECC, RSA
from Crypto.Hash import SHA256, SHA384, SHA512, CMAC
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Util.Padding import pad, unpad
from pyasn1.codec.der import decoder
from pyasn1.type import univ, namedtype

from common.utils.enum.algo import Algo
from common.utils.enum.encr_mode import EncrMode
from common.utils.enum.pad_mode import PadMode

class RSAPk(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('public_exponent', univ.Integer())
    )

class Utils():

    @staticmethod
    def serialize_pk(pk_obj, format = 'DER'):
        if isinstance(pk_obj, RSA.RsaKey) or isinstance(pk_obj, ECC.EccKey):
            return pk_obj.export_key(format=format)
        else:
            raise TypeError("invalid pk object")

    @staticmethod
    def serialize_sk(sk_obj, format = 'DER', algo: Algo = Algo.R2K):
        if algo in [Algo.R2K, Algo.R3K, Algo.R4K]:
            sk_der = sk_obj.export_key(format=format, pkcs=8)
        else: # for ecc
            sk_der = sk_obj.export_key(format=format)
        return sk_der
    
    @staticmethod
    def deserialize_pk(pk_der: bytes) -> Union[RSA.RsaKey, ECC.EccKey]:
        _spki = keys.PublicKeyInfo.load(pk_der)
        _algo = _spki.algorithm
        if _algo == "rsa":
            return RSA.import_key(pk_der)
        elif _algo == "ec":
            return ECC.import_key(pk_der)
        else:
            raise TypeError("invalid pk algorithm")

    @staticmethod
    def deserialize_sk(sk_der: bytes):
        _ski = keys.PrivateKeyInfo.load(sk_der)
        _algo = _ski.algorithm
        if _algo == "rsa":
            return RSA.import_key(sk_der)
        elif _algo == "ec":
            return ECC.import_key(sk_der)
        else:
            raise TypeError("invalid sk algorithm")

    @staticmethod
    def get_width(in_algo: Algo):
        if in_algo in {Algo.ECP256, Algo.ECP384, Algo.ECP521}:
            algorithm = "ec"
            if in_algo == Algo.ECP256:
                oid = '1.2.840.10045.3.1.7'
                width = 32
            elif in_algo == Algo.ECP521:
                oid = '1.3.132.0.35'
                width = 66
            else:
                oid =  '1.3.132.0.34'
                width = 48
        return algorithm, oid, width
    
    @staticmethod
    def gen_key(in_algo: Algo):
        # get the parameters for the kp api
        if in_algo == Algo.ECP256:
            curve = 'P-256'
        elif in_algo == Algo.ECP521:
            curve = 'P-521'
        elif in_algo == Algo.ECP384:
            curve = 'P-384'
        elif in_algo == Algo.R2K:
            mod = 2048
        elif in_algo == Algo.R3K:
            mod = 3072
        elif in_algo == Algo.R4K:
            mod = 4096
        # call the API
        if in_algo in {Algo.ECP256, Algo.ECP384, Algo.ECP521}:
            sk = ECC.generate(curve=curve)
        elif in_algo in {Algo.R2K, Algo.R3K, Algo.R4K}:
            sk = RSA.generate(bits=mod)
        else:
            raise ValueError("invalid algo!")
        pk = sk.public_key()
        return pk, sk

    @staticmethod 
    def load_cert_der(in_der_cert: bytes) -> x509.Certificate:
        return x509.Certificate.load(in_der_cert)

    @staticmethod 
    def extract_pk(in_cert: bytes):
        cert_obj = Utils.load_cert_der(in_cert)
        pk_info = cert_obj['tbs_certificate']['subject_public_key_info']
        algo = pk_info['algorithm']['algorithm'].native
        if algo in ['rsa', 'rsa_encryption']:
            pk_obj = RSA.import_key(in_cert)
        else: # ecc
            pk_obj = ECC.import_key(in_cert)
        pk_der = Utils.serialize_pk(pk_obj)
        return pk_der

    @staticmethod
    def extract_sign_algo(in_cert: bytes) -> Algo:
        cert_obj = Utils.load_cert_der(in_cert)
        algo = cert_obj['tbs_certificate']['signature']['algorithm'].native
        if algo == 'sha256_ecdsa':
            return Algo.ECP256
        elif algo == 'sha384_ecdsa':
            return Algo.ECP384
        elif algo == 'sha512_ecdsa':
            return Algo.ECP521
        elif algo == 'sha256_rsa':
            return Algo.R2K
        elif algo == 'sha384_rsa':
            return Algo.R3K
        elif algo == 'sha512_rsa':
            return Algo.R4K
        else:
            raise ValueError("unsupported algo!")
        

    @staticmethod
    def sign(in_data, issuer_sk, in_algo) -> bytes:
        if in_algo in [Algo.ECP256, Algo.ECP384, Algo.ECP521]:
            _signer = DSS.new(key=issuer_sk, mode='fips-186-3', encoding='der')
        elif in_algo in [Algo.R2K, Algo.R3K, Algo.R4K]:
            _signer = pkcs1_15.new(issuer_sk)
        hash_obj = Utils._get_hash_obj(in_algo)
        hash_obj.update(in_data)
        sign_data = _signer.sign(hash_obj)
        return sign_data
    
    @staticmethod
    def verify(data, pk_obj, algo, signature) -> bool:
        # construct the hash
        hash_obj = Utils._get_hash_obj(algo)
        hash_obj.update(data)
        # verify
        ret = False
        if algo in [Algo.ECP256, Algo.ECP384, Algo.ECP521]:
            _verifier = DSS.new(key=pk_obj, mode='fips-186-3', encoding='der')
            try:
                _verifier.verify(hash_obj, signature)
                ret =  True
            except Exception as e:
                print(f"verify failed {str(e)}")
                ret = False
        elif algo in [Algo.R2K, Algo.R3K, Algo.R4K]:
            try:
                pkcs1_15.new(pk_obj).verify(hash_obj, signature)
                ret =  True
            except Exception as e:
                print(f"verify failed {str(e)}")
                ret =  False
        return ret

    @staticmethod
    def _get_encr_mode(encr_mode: EncrMode, algo: Algo):
        mode = None
        if algo in [Algo.A128, Algo.A192, Algo.A256]:
            # legacy requirement to support ECB
            if encr_mode == EncrMode.ECB:
                # nosonar python:S5542 - AES ECB required for legacy system compatibility
                mode = AES.MODE_ECB 
            elif encr_mode in [EncrMode.CBC, EncrMode.CBC_PAD]:
                mode = AES.MODE_CBC
            elif encr_mode == EncrMode.GCM:
                mode = AES.MODE_GCM
            else: 
                raise ValueError("invalid encr mode!")
        elif algo == Algo.TDES:
            if encr_mode == EncrMode.ECB:
                # nosonar python:S5547 - TDES ECB required for legacy system compatibility
                mode = DES3.MODE_ECB
            elif encr_mode in [EncrMode.CBC, EncrMode.CBC_PAD]:
                mode = DES3.MODE_CBC
            else: 
                raise ValueError("invalid encr mode!")
        return mode

    @staticmethod
    def _pad(data: bytes, pad_size: int) -> bytes:
        return pad(data, pad_size)
    
    @staticmethod
    def _unpad(data: bytes, pad_size: int) -> bytes:
        return unpad(data, pad_size)

    @staticmethod
    def _get_cipher(algo, encr_mode, in_key, mode, iv):
        if algo in [Algo.A128, Algo.A192, Algo.A256]:
            if encr_mode == EncrMode.ECB:
                cipher = AES.new(key=in_key, mode=mode)
            elif encr_mode == EncrMode.GCM:
                cipher = AES.new(key=in_key, mode=mode, nonce=iv)
            else:
                cipher = AES.new(key=in_key, mode=mode, iv=iv)
        elif algo is Algo.TDES:
            if encr_mode == EncrMode.ECB:
                # nosonar python:S5547 - TDES required for legacy system compatibility
                cipher = DES3.new(key=in_key, mode=mode) 
            else:
                # nosonar python:S5547 - TDES required for legacy system compatibility
                cipher = DES3.new(key=in_key, mode=mode, iv=iv)
        return cipher

    @staticmethod
    def encrypt(encr_mode: EncrMode, algo: Algo, data: bytes, in_key: bytes, iv: bytes = None):
        # get the mode
        mode = Utils._get_encr_mode(encr_mode, algo)
        cipher = Utils._get_cipher(algo, encr_mode, in_key, mode, iv)
        if encr_mode != EncrMode.GCM:
            encr_data = cipher.encrypt(data)
            tag = None
        else:
            encr_data, tag = cipher.encrypt_and_digest(data)
        return encr_data, tag

    @staticmethod
    def decrypt(
        encr_mode: EncrMode, algo: Algo, encr_data: bytes, in_key: bytes, iv: bytes = None, 
        tag: bytes = None):
        # get the mode
        mode = Utils._get_encr_mode(encr_mode, algo)
        cipher = Utils._get_cipher(algo, encr_mode, in_key, mode, iv)
        if encr_mode != EncrMode.GCM:
            decr_data = cipher.decrypt(encr_data)
        else:
            decr_data = cipher.decrypt_and_verify(encr_data, tag)
        return decr_data

    @staticmethod
    def sym_sign(algo: Algo, key: bytes, data: bytes) -> bytes:
        cmac = CMAC.new(key, ciphermod=AES)
        cmac.update(data)
        return cmac.digest()

    @staticmethod
    def sk_decrypt(in_enc_data, in_sk_obj, in_padding:PadMode = None):
        if in_padding == None:
            # nosonar python:S5542 - PKCS v1.5 padding required for legacy system compatibility
            cipher = PKCS1_v1_5.new(key=in_sk_obj) 
        elif in_padding == PadMode.OAEP:
            cipher = PKCS1_OAEP.new(key=in_sk_obj, hashAlgo=SHA256)
        sentinel = get_random_bytes(16)
        return cipher.decrypt(ciphertext=in_enc_data, sentinel=sentinel)

    @staticmethod
    def pk_encrypt(in_data: bytes, in_pk_obj, in_padding: PadMode = None):
        if in_padding == None:
            # nosonar python:S5542PKCS v1.5 padding required for legacy system compatibility
            cipher = PKCS1_v1_5.new(key=in_pk_obj) 
        elif in_padding == PadMode.OAEP:
            cipher = PKCS1_OAEP.new(key=in_pk_obj, hashAlgo=SHA256)
        return cipher.encrypt(in_data)

    @staticmethod
    def load_crl(in_crl_der):
        return crl.CertificateList.load(in_crl_der)

    @staticmethod
    def get_rev_certs(in_crl_der: bytes) -> list:
        crl_obj = Utils.load_crl(in_crl_der)
        rev_certs = crl_obj["tbs_cert_list"]["revoked_certificates"]
        new_rev_certs = []
        for itr in rev_certs:
            rev_cert = crl.RevokedCertificate()
            # 1. assign serial number to user_certificate
            rev_cert['user_certificate'] = itr["user_certificate"]
            rev_cert['revocation_date'] = itr["revocation_date"]
            new_rev_certs.append(rev_cert)
        return new_rev_certs
		
    @staticmethod
    def _serialize_pk_uncompressed(pk_obj: ECC.EccKey):
        _mod_bytes = pk_obj.pointQ.size_in_bytes()
        x_bytes = pk_obj.pointQ.x.to_bytes(_mod_bytes)
        y_bytes = pk_obj.pointQ.y.to_bytes(_mod_bytes)
        return x_bytes, y_bytes
    
    @staticmethod
    def serialize_pk_uncompressed(pk):
        x_bytes, y_bytes = Utils._serialize_pk_uncompressed(pk)
        return (b'\x04' + x_bytes + y_bytes)
        
    @staticmethod
    def get_sign_algo(in_algo: Algo) -> str:
        if in_algo in {Algo.ECP256, Algo.S256EC}:
            const_algo = 'sha256_ecdsa'
        elif in_algo == Algo.ECP384:
            const_algo = 'sha384_ecdsa'
        elif in_algo == Algo.ECP521:
            const_algo = 'sha512_ecdsa'
        elif in_algo in {Algo.R2K, Algo.S256R}:
            const_algo = 'sha256_rsa'
        elif in_algo == Algo.R3K:
            const_algo = 'sha384_rsa'
        elif in_algo == Algo.R4K:
            const_algo = 'sha512_rsa'
        else:
            raise ValueError("unsupported algo")
        return const_algo

    @staticmethod
    def _get_hash_obj(algo: Algo):
        hash_obj = SHA256.new()
        if algo in [Algo.ECP384, Algo.R3K]:
            hash_obj = SHA384.new()
        elif algo in [Algo.ECP521, Algo.R4K]:
            hash_obj = SHA512.new()
        return hash_obj

    @staticmethod
    def hash(algo: Algo, in_data: bytes) -> bytes:
        hash_obj = Utils._get_hash_obj(algo)
        hash_obj.update(in_data)
        return hash_obj.digest()

    @staticmethod
    def urlsafe_b64encode(data: bytes) -> bytes:
        return urlsafe_b64encode(data)

    @staticmethod
    def urlsafe_b64decode(data: bytes) -> bytes:
        return urlsafe_b64decode(data)

    @staticmethod
    def load_csr(in_csr: str):
        return csr.CertificationRequest.load(bytes.fromhex(in_csr))

    @staticmethod
    def get_algo_curve(in_algo: Algo):
        if in_algo == Algo.ECP256:
            named_curve = 'secp256r1'
            const_algo = 'sha256_ecdsa'
        elif in_algo == Algo.ECP384:
            named_curve = 'secp384r1'
            const_algo = 'sha384_ecdsa'
        elif in_algo == Algo.ECP521:
            named_curve = 'secp521r1'
            const_algo = 'sha512_ecdsa'
        else:
            raise ValueError("unsupported algo!")
        return named_curve, const_algo

    @staticmethod
    def xor(in_ba1, in_ba2):
        if len(in_ba1) != len(in_ba2):
            raise ValueError("ba must be same len!")
        ret = [a^b for a,b in zip(in_ba1, in_ba2)]
        return bytes(ret)

    
    @staticmethod
    def extract_mod_exp(in_der):
        asn1seq, _ = decoder.decode(in_der, asn1Spec=univ.Sequence())
        print(f"mod: {asn1seq[0]}")
        print(f"type of mod: {type(asn1seq[0])}")
        print(f"exp: {asn1seq[1]}")
        _mod = int(asn1seq[0])
        _exp = int(asn1seq[1])
        mod_bytes = _mod.to_bytes((_mod.bit_length()+7)//8, byteorder='big')
        exp_bytes = _exp.to_bytes((_exp.bit_length()+7)//8, byteorder='big')
        print(f"mod: {mod_bytes.hex()}")
        print(f"exp: {exp_bytes.hex()}")
        return mod_bytes, exp_bytes

    @staticmethod
    def construct_pk(algo: Algo, x_bytes: bytes, y_bytes: bytes):
        # constgruct the algo, parameters and pk_value
        if algo in {Algo.ECP256, Algo.ECP384, Algo.ECP521}:
            algorithm = "ec"
            if algo == Algo.ECP256:
                oid = '1.2.840.10045.3.1.7'
            elif algo == Algo.ECP521:
                oid = '1.3.132.0.35'
            else:
                oid =  '1.3.132.0.34'
            pk_value = keys.ECPointBitString(
                value= (b'\x04' + x_bytes + y_bytes)
            )
            parameters = keys.NamedCurve(oid)
        elif algo in {Algo.R2K, Algo.R3K, Algo.R4K}:
            algorithm = "rsa"
            parameters = None
            pk_value = keys.RSAPublicKey({
                'modulus': int.from_bytes(y_bytes, byteorder='big'),
                'public_exponent': int.from_bytes(x_bytes, byteorder='big')
            })
        else:
            raise ValueError("unsupported algo type")
        # construct the subject pk info
        subject_pk_info = keys.PublicKeyInfo({
                'algorithm': keys.PublicKeyAlgorithm({
                    'algorithm': algorithm,
                    'parameters': parameters
                }),
                'public_key': pk_value
            })
        return subject_pk_info.dump()

