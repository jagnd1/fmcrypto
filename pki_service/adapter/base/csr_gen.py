from abc import ABC, abstractmethod
from asn1crypto import csr, keys, core

from common.utils.enum.algo import Algo
from common.utils.crypto import Utils as NewUtils

class CsrGen(ABC):

    def __init__(self):
        print("abs csr gen: ")
        self.issuer_sk: bytes = b''
        self.pk_obj = None
        self.cert_req_info = None
        self.sign_data = None
        self.cert_req = None
    
    @abstractmethod
    def sign(self, data: bytes, in_algo: Algo) -> bytes:
        """ sign will be implemented in the child class """
        pass

    def cert_req_info_build(self, sub: dict[str, str], in_algo: Algo) -> bytes:

        if in_algo in {Algo.ECP256, Algo.ECP384, Algo.ECP521}:
            algorithm = "ec"
            if in_algo == Algo.ECP256:
                oid = '1.2.840.10045.3.1.7'
            elif in_algo == Algo.ECP521:
                oid = '1.3.132.0.35'
            else:
                oid =  '1.3.132.0.34'
            pk_value = keys.ECPointBitString(value=NewUtils.serialize_pk_uncompressed(self.pk_obj))
            parameters = keys.NamedCurve(oid)
        elif in_algo in { Algo.R2K, Algo.R3K, Algo.R4K}:
            algorithm = "rsa"
            parameters = None
            pk_value = keys.RSAPublicKey({
                'modulus': self.pk_obj.n, 'public_exponent': self.pk_obj.e})
        else:
            raise ValueError("unsupported algo type")
        # x500 name
        x500_name = csr.Name.build({
            'country_name': sub.get('country', ''), 'state_or_province_name': sub.get('state', ''),
            'locality_name': sub.get('locale', ''), 'organization_name': sub.get('org', ''),
            'common_name': sub.get('cn', ''),})
        # cert req info build
        self.cert_req_info = csr.CertificationRequestInfo({
            'version': 0, 'subject': x500_name,
            'subject_pk_info': keys.PublicKeyInfo({
                'algorithm': keys.PublicKeyAlgorithm({
                    'algorithm': algorithm, 'parameters': parameters}),
                'public_key': pk_value
            })
        })
        return self.cert_req_info.dump()
    

    def cert_req_build(self, in_algo: Algo) -> bytes:
        const_algo = NewUtils.get_sign_algo(in_algo)
        self.cert_req = csr.CertificationRequest({
            'certification_request_info': self.cert_req_info, 
            'signature_algorithm': {'algorithm': const_algo}, 
            'signature': core.OctetBitString(self.sign_data)})
        self.csr = self.cert_req.dump()
        return self.csr

