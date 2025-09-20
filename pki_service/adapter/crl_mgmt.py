from common.utils.enum.algo import Algo
from common.utils.crypto import Utils as NewUtils
from pki_service.adapter.base.crl_mgmt import CrlMgmt as BaseCrlMgmt
from pki_service.adapter.server_cli import ServerCli, crypto_hsm


"""
view crl: 
openssl crl -in test.crl -text -noout

sample crl:
-----BEGIN X509 CRL-----
...
-----END X509 CRL-----
"""

class CrlMgmt(BaseCrlMgmt):

    def __init__(self, server_cli: ServerCli):
        super().__init__()
        self.server_cli = server_cli
        print("gp crl mgmt: ")
    
    async def sign(self, data: bytes, sk_lmk: str, algo: Algo) -> bytes:
        ep: str = f"gen_sign?hsm_name={crypto_hsm}"
        data = {
            "msg": f"{data.hex()}", "sk_lmk": f"{sk_lmk}", "algo": f"{Algo.get_algo_str(algo)}",}
        resp = await self.server_cli.exchange(ep, data)
        if resp and resp['status'] == "success":
            self.sign_data = bytes.fromhex(resp['signature'])
            return self.sign_data

async def crl_mgmt(
    server_cli: ServerCli, cert: bytes, issuer_cert: bytes, algo: Algo, issuer_sk: str, 
    rev_certs: list = None):
    # build the crl mgmt object
    crl_mgmt_obj = CrlMgmt(server_cli)
    tbs_cert_list = crl_mgmt_obj.build_tbs_cert_list(cert, issuer_cert, algo, rev_certs)
    sign_data = await crl_mgmt_obj.sign(tbs_cert_list, issuer_sk, algo)
    if sign_data is not None:
        cert_list = crl_mgmt_obj.build_cert_list()
        return NewUtils.urlsafe_b64encode(cert_list)
