from asn1crypto import cms, core, algos
from asn1crypto import x509 as asn1x509
import os

from common.utils.enum.algo import Algo
from common.utils.enum.encr_mode import EncrMode
from common.utils.enum.pad_mode import PadMode
from common.utils.gp.asym_key import AsymKey
from common.utils.gp.sym_key import SymKey
from common.utils.crypto import Utils as NewUtils

class Tr34:

    def __init__(self):
        print("tr34 init")
        self.sym_key_obj = SymKey()

    def _build_ri(self, enc_cert_der: bytes, key: bytes):
        enc_cert = asn1x509.Certificate.load(enc_cert_der)
        _pk_der = NewUtils.extract_pk(enc_cert_der)
        print(f"build ri: pk der: {_pk_der.hex()}")
        encr_pk_obj = NewUtils.deserialize_pk(_pk_der)
        ek = NewUtils.pk_encrypt(key, encr_pk_obj, PadMode.OAEP)
        print(f"ek: {ek.hex()}")
        ri = cms.RecipientInfo({
            'ktri': cms.KeyTransRecipientInfo({
                'version': "v0",
                'rid': cms.RecipientIdentifier({
                    'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                        'issuer': enc_cert["tbs_certificate"]["issuer"],
                        'serial_number': enc_cert["tbs_certificate"]["serial_number"],
                    }),
                }),
                'key_encryption_algorithm': cms.KeyEncryptionAlgorithm({
                    'algorithm': cms.KeyEncryptionAlgorithmId('rsaes_oaep'),
                    'parameters': algos.RSAESOAEPParams({
                        'hash_algorithm': algos.DigestAlgorithm({'algorithm': "sha256"}),
                        'mask_gen_algorithm': {
                            'algorithm': "mgf1",
                            'parameters': {'algorithm': "sha256"}
                        }
                    })
                }),
                'encrypted_key': core.OctetString(ek)
            })
        })
        return ri
    
    def _get_sym_algo(self, algo: Algo):
        if algo == Algo.TDES:
            algo_str = "tripledes_3key"
        elif algo == Algo.A128:
            algo_str = "aes128_cbc"
        elif algo == Algo.A192:
            algo_str = "aes192_cbc"
        elif algo == Algo.A256:
            algo_str = "aes256_cbc"
        else:
            raise ValueError("unsupported sym algo!")
        return algo_str
    
    def build_ed(self, enc_cert: bytes, data: bytes, sym_algo: Algo):
        ke = self.sym_key_obj.gen_key(sym_algo)
        print(f"ke lmk: {ke.hex()}")
        ke_clear = self.sym_key_obj.get_key_val(sym_algo, ke)
        print(f"ke clear: {ke_clear.hex()}")
        iv = os.urandom(16)
        print(f"iv: {iv.hex()}")
        ec = self.sym_key_obj.encrypt(sym_algo, EncrMode.CBC, ke, iv, data)
        print(f"ec: {ec.hex()}")
        return cms.EnvelopedData({
                'version': "v0",
                'recipient_infos': [self._build_ri(enc_cert, ke_clear)],
                'encrypted_content_info': {
                    'content_type': "data",
                    'content_encryption_algorithm': cms.EncryptionAlgorithm({
                        'algorithm': cms.EncryptionAlgorithmId(self._get_sym_algo(sym_algo)),
                        'parameters': iv
                    }),
                    'encrypted_content': ec
                }
            })
    
    def _build_si(self, signer_cert_der: bytes, signer_sk: bytes, digest_algo: str, hash_data: bytes):
        signer_cert = asn1x509.Certificate.load(signer_cert_der)
        asym_key_obj = AsymKey()
        kbh = bytes.fromhex("42303031364b31544430304e30303030") # T O D O: parameterize and finalize
        cms.CMSAttributeType._map['1.2.840.113549.1.7.1'] = "data"
        cms.CMSAttribute._oid_specs['data'] = cms.SetOfOctetString
        cms.CMSAttributeType._map['1.2.840.113549.1.9.25.3'] = "random_nonce"
        cms.CMSAttribute._oid_specs['random_nonce'] = cms.SetOfOctetString
        s_attrs = cms.CMSAttributes([
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('content_type'),
                'values': [cms.ContentType('enveloped_data')]
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('message_digest'),
                'values': [hash_data]
            }),
            cms.CMSAttribute({
                'type': "data",
                'values': [kbh]
            }),
            cms.CMSAttribute({
                'type': "random_nonce",
                'values': [os.urandom(16)]
            })
        ])
        sign_data = asym_key_obj.sign(Algo.R2K, signer_sk, s_attrs.dump())
        print(f"sign data: {sign_data.hex()}")
        si = cms.SignerInfo({
            'version': "v1",
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': signer_cert["tbs_certificate"]["issuer"],
                    'serial_number': signer_cert["tbs_certificate"]["serial_number"],
                }),
            }),
            'digest_algorithm': algos.DigestAlgorithm({'algorithm': algos.DigestAlgorithmId(digest_algo)}),
            'signed_attrs': s_attrs,
            'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': algos.SignedDigestAlgorithmId("sha256_rsa")}),
            'signature': sign_data
        })
        print(f"si: {si.dump().hex()}")
        return si

    def build_sd(self, digest_algo: str, ed_obj: cms.EnvelopedData, signer_cert_der: bytes, signer_sk: bytes):
        hash_ed = NewUtils.hash(Algo.R2K, ed_obj.dump())
        return cms.ContentInfo({
            'content_type': "signed_data",
            'content': cms.SignedData({
                'version': "v1",
                'digest_algorithms': [cms.DigestAlgorithm({'algorithm': algos.DigestAlgorithmId(digest_algo)})],
                'encap_content_info': cms.ContentInfo({
                    'content_type': "enveloped_data",
                     'content': ed_obj
                }),
                'signer_infos': [self._build_si(signer_cert_der, signer_sk, digest_algo, hash_ed)]
            })
        }).dump()
