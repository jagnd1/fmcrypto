from abc import ABC, abstractmethod
from typing import Any
from asn1crypto import keys as asn1keys, x509 as asn1x509, csr
from Crypto.PublicKey import ECC, RSA
from datetime import datetime, timezone, timedelta 
import time

from common.utils.enum.algo import Algo
from common.utils.enum.cert_level import CertLevel
from common.utils.crypto import Utils as NewUtils


class CertGen(ABC):
    def __init__(self):
        print("abs cert gen: ")
        self.tbs_cert: asn1x509.TbsCertificate = None
        self.csr_obj: csr = None
        self.signature = None
        self.cert_level = CertLevel.ROOT_CA
        self.pk = None

    def _get_sub_name(self, in_sub):
        return asn1x509.Name.build({
            'country_name': in_sub.native.get('country_name', None),
            'state_or_province_name': in_sub.native.get('state_or_province_name', None),
            'locality_name': in_sub.native.get('locality_name', None),
            'organization_name': in_sub.native.get('organization_name', None),
            'common_name': in_sub.native.get('common_name', None),
        })

    def _get_curve(self, in_algo: Algo) -> Any:
        if in_algo == Algo.ECP256:
            curve = "P-256"
        elif in_algo == Algo.ECP521:
            curve = "P-521"
        elif in_algo == Algo.ECP384:
            curve = "P-384"
        return curve
    
    def _get_ec_point(self, width, x, y):
        x_bytes = x.to_bytes(width, byteorder='big')
        y_bytes = y.to_bytes(width, byteorder='big')
        return b'\x04' + x_bytes + y_bytes

    def tbs_cert_build(
        self, csr_data: str, in_algo: Algo, in_cert_level: CertLevel, 
        in_issuer_cert: str) -> bytes:
        # prepare the request parameters
        self.cert_level = in_cert_level
        print("in cert level: ", in_cert_level)
        self.csr_obj = NewUtils.load_csr(csr_data)
        # convert x500name to x509.Name
        subject_name = self.csr_obj["certification_request_info"]["subject"]
        # construct issuer_sub_name from issuer cert
        if in_cert_level != CertLevel.ROOT_CA:
            issuer_sub = NewUtils.load_cert_der(bytes.fromhex(in_issuer_cert)).subject
            issuer_name = self._get_sub_name(issuer_sub)
            signing_algo = NewUtils.extract_sign_algo(bytes.fromhex(in_issuer_cert))
        else:
            issuer_name = subject_name
            signing_algo = in_algo
        # extract and convert the public key
        pk_info = self.csr_obj["certification_request_info"]["subject_pk_info"]
        # extract and convert the public key
        if in_algo in {Algo.ECP256, Algo.ECP384, Algo.ECP521}:
            # 1. algo
            algorithm, _, width = NewUtils.get_width(in_algo)
            # 2. pk
            ec_point = pk_info["public_key"].native
            print(f"ec_point: {ec_point.hex()}")
            self.pk = ECC.construct(
                curve=self._get_curve(in_algo), 
                point_x=int.from_bytes(ec_point[1:width+1], byteorder='big'), 
                point_y=int.from_bytes(ec_point[width+1:], byteorder='big'))
            pk_value = asn1keys.ECPointBitString(value=ec_point)
            # 3. params
            _, const_sign_algo = NewUtils.get_algo_curve(signing_algo)
            named_curve, _ = NewUtils.get_algo_curve(in_algo)

            parameters = asn1keys.ECDomainParameters({'named': named_curve})
        elif in_algo in {Algo.R2K, Algo.R3K, Algo.R4K}:
            # 1. algo
            algorithm = 'rsa'
            # 2. pk
            pk_info_native = pk_info["public_key"].native
            mod = pk_info_native["modulus"]
            exp = pk_info_native["public_exponent"]
            pk_value = asn1keys.RSAPublicKey({
                'modulus': mod,
                'public_exponent': exp
            })
            self.pk = RSA.construct((mod, exp))
            # 3. params
            parameters = None
            const_sign_algo = NewUtils.get_sign_algo(signing_algo)
        else:
            raise ValueError("invalid algo in tbs cert build")
        
        sub_pk_info = asn1keys.PublicKeyInfo({
            'algorithm': asn1keys.PublicKeyAlgorithm({
                'algorithm': algorithm, 'parameters': parameters,}),
            'public_key': pk_value})
        # sub key id
        _pk_der = NewUtils.serialize_pk(self.pk)
        ski_digest = NewUtils.hash(in_algo, _pk_der)
        # construct the ski extension
        ski_extn = asn1x509.Extension({
            'extn_id': '2.5.29.14', 'critical': False, 'extn_value': ski_digest})
        extn_list = [ski_extn]
        if self.cert_level == CertLevel.ROOT_CA or self.cert_level == CertLevel.INT_CA:                
            # basic constraints
            bc = asn1x509.BasicConstraints({'ca': True, 'path_len_constraint': None})
            bc_extn = asn1x509.Extension({
                'extn_id': '2.5.29.19', 'critical': True, 'extn_value': bc})
            extn_list.append(bc_extn)
            # key usage
            ku = asn1x509.KeyUsage({'digital_signature', 'key_cert_sign', 'crl_sign'})
            ku_extn = asn1x509.Extension({
                'extn_id': '2.5.29.15', 'critical': True, 'extn_value': ku})
            extn_list.append(ku_extn)
        # other credentials
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=365)
        # create a self-signed certificate structure without signing it
        self.tbs_cert = asn1x509.TbsCertificate({
            'version': 'v3', 'serial_number': int(time.time_ns()), 'issuer': issuer_name,
            'subject': subject_name,
            'signature': {'algorithm': const_sign_algo, 'parameters': None,},
            'validity': {
                'not_before': asn1x509.Time({'utc_time': not_before}),
                'not_after': asn1x509.Time({'utc_time': not_after}),},
            'subject_public_key_info': sub_pk_info, 'extensions': extn_list,
        })
        return self.tbs_cert.dump()

    @abstractmethod
    def sign(self, message: bytes, issuer_sk: str, algo: Algo) -> bytes:
        """ sign will be implemented in the child class """
        pass

    def cert_build(self, signature: bytes, in_algo: Algo) -> bytes:
        const_sign_algo = NewUtils.get_sign_algo(in_algo)
        cert = asn1x509.Certificate({
            'tbs_certificate': self.tbs_cert,
            'signature_algorithm': {'algorithm': const_sign_algo, 'parameters': None,},
            'signature_value': signature,
        })
        return cert.dump()
