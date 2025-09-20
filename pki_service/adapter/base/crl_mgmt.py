from abc import ABC, abstractmethod
from asn1crypto import crl, x509 as asn1x509
from datetime import datetime, timedelta, timezone

from common.utils.enum.algo import Algo
from common.utils.crypto import Utils as NewUtils


class CrlMgmt(ABC):
    
    def __init__(self):
        print("abs crl mgmt: ")
        self.algo = Algo.ECP521
        self.tbs_cert_list = None
        self.sign_data = None
        self.crl = None

    def build_tbs_cert_list(
        self, cert: bytes, issuer_cert: bytes, in_algo: Algo, in_rev_certs: list =None) -> bytes:
        # issuer sub
        issuer_cert_obj = NewUtils.load_cert_der(issuer_cert)
        issuer_sub = issuer_cert_obj.subject
        issuer_name = asn1x509.Name.build({
            'country_name': issuer_sub.native.get('country_name', None),
            'state_or_province_name': issuer_sub.native.get('state_or_province_name', None),
            'locality_name': issuer_sub.native.get('locality_name', None),
            'organization_name': issuer_sub.native.get('organization_name', None),
            'common_name': issuer_sub.native.get('common_name', None),
        })
        # time update
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=30)
        # revoc cert
        rev_cert = crl.RevokedCertificate()
        cert_obj = NewUtils.load_cert_der(cert)
        rev_cert['user_certificate'] = cert_obj['tbs_certificate']['serial_number']
        rev_cert['revocation_date'] = asn1x509.Time({'utc_time': not_before})
        if not in_rev_certs:
            in_rev_certs = []
        in_rev_certs.append(rev_cert)
        # extn
        _extns = issuer_cert_obj['tbs_certificate']['extensions']
        ski = None
        for _ext in _extns:
            if _ext['extn_id'].native == 'key_identifier':
                ski = _ext['extn_value'].native
                break
        if ski is None:
            raise ValueError("key id extn not found in the cert!")
        aki = asn1x509.AuthorityKeyIdentifier({'key_identifier': ski})
        aki_extn = crl.TBSCertListExtension({
            'extn_id': '2.5.29.35', 'critical': False,'extn_value': aki,})
        crl_tbs_cert_list_extns = crl.TBSCertListExtensions()
        crl_tbs_cert_list_extns.append(aki_extn)
        # add reason
        rc = asn1x509.ReasonFlags({'privilege_withdrawn'})
        r_extn = crl.TBSCertListExtension({
            'extn_id': '2.5.29.21', 'critical': False, 'extn_value': rc.dump(),})
        crl_tbs_cert_list_extns.append(r_extn)
        # sign
        self.algo = NewUtils.get_sign_algo(in_algo)
        # build tbscertlist
        tbs_cert_list = crl.TbsCertList({
            'signature': {'algorithm': self.algo, 'parameters': None,}, 'issuer': issuer_name,
            'this_update': asn1x509.Time({'utc_time': not_before}),
            'next_update': asn1x509.Time({'utc_time': not_after}),
            'revoked_certificates': in_rev_certs, 'crl_extensions': crl_tbs_cert_list_extns,
        })
        self.tbs_cert_list = tbs_cert_list
        return tbs_cert_list.dump()
    
    @abstractmethod
    def sign(self, message: bytes, issuer_sk: str, algo: Algo) -> bytes:
        """ sign will be implemented in the child class """
        pass

    def build_cert_list(self) -> bytes:
        crl_obj = crl.CertificateList({
            'tbs_cert_list': self.tbs_cert_list,
            'signature_algorithm': {'algorithm': self.algo,'parameters': None,},
            'signature': self.sign_data,
        })
        self.crl = crl_obj.dump()
        return self.crl
    
    def get_crl(self):
        return self.crl
