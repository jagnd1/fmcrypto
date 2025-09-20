from abc import ABC, abstractmethod
from asn1crypto import x509 as asn1x509
from datetime import datetime, timezone, timedelta

from common.utils.enum.algo import Algo
from common.utils.crypto import Utils as NewUtils


class CertRenew(ABC):

    def __init__(self):
        print("abs cert renew: ")
        self.tbs_cert = None

    def tbs_cert_build(self, in_cert: str, in_issuer_cert: str, in_algo: Algo) -> bytes:
        cert_asn1 = asn1x509.Certificate.load(bytes.fromhex(in_cert))
        tbs_cert = cert_asn1['tbs_certificate']
        # extract the serial number
        serial_no = tbs_cert['serial_number']
        issuer_sub_name = tbs_cert['issuer']
        sub_name = tbs_cert['subject']
        spki = tbs_cert['subject_public_key_info']
        extns = tbs_cert['extensions']
        # extract the sign algorithm
        _sign_algo = in_algo
        if in_issuer_cert:
            _sign_algo = NewUtils.extract_sign_algo(bytes.fromhex(in_issuer_cert))
        const_sign_algo = NewUtils.get_sign_algo(_sign_algo)
        # extract the validity
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=365)
        # build the tbs cert
        self.tbs_cert = asn1x509.TbsCertificate({
            'version': 'v3', 'serial_number': serial_no, 'issuer': issuer_sub_name, 
            'subject': sub_name,
            'signature': {'algorithm': const_sign_algo, 'parameters': None,},
            'validity': {
                'not_before': asn1x509.Time({'utc_time': not_before}),
                'not_after': asn1x509.Time({'utc_time': not_after}),
            },
            'subject_public_key_info': spki, 'extensions': extns,
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
