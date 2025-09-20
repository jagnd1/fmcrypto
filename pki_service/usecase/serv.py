from enum import Enum
from common.utils.enum.algo import Algo
from common.utils.enum.cert_level import CertLevel
from common.utils.crypto import Utils as NewUtils
from pki_service.app.schema.serv import CertCreateReq, CertResp, CertUpdate, \
    CrlMgmtReq, CrlMgmtResp
from pki_service.adapter.crl_mgmt import crl_mgmt
from pki_service.adapter.cert_renew import renew_cert
from pki_service.adapter.cert_gen import cert_gen
from pki_service.adapter.server_cli import ServerCli

class Status(Enum):
    SUCCESS = "success"
    ERROR = "error"

class ServerUsecase:
    def __init__(self, server_cli: ServerCli):
        self.server_cli = server_cli

    async def create_cert(self, cert_obj: CertCreateReq) -> CertResp:
        algo = Algo.get_str_algo(cert_obj.algo)
        cert_level = CertLevel.get_cert_level(cert_obj.cert_level)
        csr = (NewUtils.urlsafe_b64decode(cert_obj.csr)).hex()
        if cert_obj.issuer_cert:
            issuer_cert = (NewUtils.urlsafe_b64decode(cert_obj.issuer_cert)).hex()
        else:
            issuer_cert = None
        cert = await cert_gen(self.server_cli, csr, cert_obj.sk_lmk, cert_level, algo, 
                               issuer_cert)
        return CertResp(status=Status.SUCCESS, cert=cert)

    async def renew_cert(self, cert_update_obj: CertUpdate) -> CertResp:
        algo = Algo.get_str_algo(cert_update_obj.algo)
        if cert_update_obj.issuer_cert:
            issuer_cert = (NewUtils.urlsafe_b64decode(cert_update_obj.issuer_cert)).hex()
        else:
            issuer_cert = None
        if cert_update_obj.cert:
            cert = (NewUtils.urlsafe_b64decode(cert_update_obj.cert)).hex()
        else:
            cert = None
        renewed_cert = await renew_cert(self.server_cli, cert, issuer_cert, algo, 
                                         cert_update_obj.sk_lmk)
        return CertResp(status=Status.SUCCESS, cert=renewed_cert)

    async def crl_mgmt(self, crl_mgmt_req: CrlMgmtReq):
        if crl_mgmt_req.cert:
            cert = (NewUtils.urlsafe_b64decode(crl_mgmt_req.cert))
        else:
            cert = None
        if crl_mgmt_req.issuer_cert:
            issuer_cert = (NewUtils.urlsafe_b64decode(crl_mgmt_req.issuer_cert))
        else:
            issuer_cert = None
        algo = Algo.get_str_algo(crl_mgmt_req.algo)
        if crl_mgmt_req.crl:
            crl = (NewUtils.urlsafe_b64decode(crl_mgmt_req.crl)).hex()
            if len(crl) > 0:
                rev_certs: list = NewUtils.get_rev_certs(bytes.fromhex(crl))
        else:
            rev_certs: list = []
        new_crl = await crl_mgmt(self.server_cli, cert, issuer_cert, algo, 
                                  crl_mgmt_req.sk_lmk, rev_certs)
        return CrlMgmtResp(status=Status.SUCCESS, crl=new_crl)
