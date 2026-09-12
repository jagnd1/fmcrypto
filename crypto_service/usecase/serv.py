from enum import Enum
from common.utils.enum.algo import Algo
from common.utils.enum.cert_level import CertLevel
from common.utils.crypto import Utils as NewUtils
from crypto_service.app.schema.serv import CertCreateReq, CertResp, CertUpdate, CrlMgmtReq, CrlMgmtResp
from crypto_service.app.schema.crypto import SignReq
from crypto_service.adapter.pki.cert_gen import CertGen
from crypto_service.adapter.pki.cert_renew import CertRenew
from crypto_service.adapter.pki.crl_mgmt import CrlMgmt
from crypto_service.usecase.crypto import CryptoUsecase


class Status(Enum):
    SUCCESS = "success"
    ERROR = "error"

class ServerUsecase:
    def __init__(self, crypto_uc: CryptoUsecase):
        self.crypto_uc = crypto_uc

    async def create_cert(self, cert_obj: CertCreateReq) -> CertResp:
        algo = Algo.get_str_algo(cert_obj.algo)
        cert_level = CertLevel.get_cert_level(cert_obj.cert_level)
        csr = NewUtils.urlsafe_b64decode(cert_obj.csr).hex()
        issuer_cert = NewUtils.urlsafe_b64decode(cert_obj.issuer_cert).hex() if cert_obj.issuer_cert else None

        gen = CertGen()
        tbs_cert = gen.tbs_cert_build(csr, algo, cert_level, issuer_cert)
        sign_algo = NewUtils.extract_sign_algo(bytes.fromhex(issuer_cert)) if issuer_cert else algo
        resp = await self.crypto_uc.gen_sign(SignReq(msg=tbs_cert.hex(), sk_lmk=cert_obj.sk_lmk, algo=Algo.get_algo_str(sign_algo)))
        cert = gen.cert_build(bytes.fromhex(resp.signature), sign_algo)
        return CertResp(status=Status.SUCCESS, cert=NewUtils.urlsafe_b64encode(cert))

    async def renew_cert(self, cert_update_obj: CertUpdate) -> CertResp:
        algo = Algo.get_str_algo(cert_update_obj.algo)
        cert = NewUtils.urlsafe_b64decode(cert_update_obj.cert).hex() if cert_update_obj.cert else None
        issuer_cert = NewUtils.urlsafe_b64decode(cert_update_obj.issuer_cert).hex() if cert_update_obj.issuer_cert else None

        gen = CertRenew()
        tbs_cert = gen.tbs_cert_build(cert, issuer_cert, algo)
        sign_algo = NewUtils.extract_sign_algo(bytes.fromhex(issuer_cert)) if issuer_cert else algo
        resp = await self.crypto_uc.gen_sign(SignReq(msg=tbs_cert.hex(), sk_lmk=cert_update_obj.sk_lmk, algo=Algo.get_algo_str(sign_algo)))
        renewed_cert = gen.cert_build(bytes.fromhex(resp.signature), sign_algo)
        return CertResp(status=Status.SUCCESS, cert=NewUtils.urlsafe_b64encode(renewed_cert))

    async def crl_mgmt(self, crl_mgmt_req: CrlMgmtReq) -> CrlMgmtResp:
        cert = NewUtils.urlsafe_b64decode(crl_mgmt_req.cert) if crl_mgmt_req.cert else None
        issuer_cert = NewUtils.urlsafe_b64decode(crl_mgmt_req.issuer_cert) if crl_mgmt_req.issuer_cert else None
        algo = Algo.get_str_algo(crl_mgmt_req.algo)
        rev_certs = []
        if crl_mgmt_req.crl:
            crl_hex = NewUtils.urlsafe_b64decode(crl_mgmt_req.crl).hex()
            if len(crl_hex) > 0:
                rev_certs = NewUtils.get_rev_certs(bytes.fromhex(crl_hex))

        gen = CrlMgmt()
        tbs = gen.build_tbs_cert_list(cert, issuer_cert, algo, rev_certs)
        resp = await self.crypto_uc.gen_sign(SignReq(msg=tbs.hex(), sk_lmk=crl_mgmt_req.sk_lmk, algo=Algo.get_algo_str(algo)))
        gen.sign_data = bytes.fromhex(resp.signature)
        new_crl = gen.build_cert_list()
        return CrlMgmtResp(status=Status.SUCCESS, crl=NewUtils.urlsafe_b64encode(new_crl))