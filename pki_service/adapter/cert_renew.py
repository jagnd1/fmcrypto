
from common.middlewares.reqid_exception import BusinessLogicException
from common.utils.enum.algo import Algo
from common.utils.crypto import Utils as NewUtils
from pki_service.adapter.base.cert_renew import CertRenew as BaseCertRenew
from pki_service.adapter.server_cli import ServerCli, crypto_hsm


class CertRenew(BaseCertRenew):

    def __init__(self, server_cli: ServerCli):
        super().__init__()
        self.server_cli = server_cli
        print("gp cert renew!")

    async def sign(self, data: bytes, sk_lmk: str, algo: Algo):
        ep: str = f"gen_sign?hsm_name={crypto_hsm}"
        data = {
            "msg": f"{data.hex()}", "sk_lmk": f"{sk_lmk}", "algo": f"{Algo.get_algo_str(algo)}",}
        resp = await self.server_cli.exchange(ep, data)
        if resp and resp['status'] == "success":
            self.sign_data = bytes.fromhex(resp['signature'])
            return self.sign_data

async def renew_cert(
    server_cli: ServerCli, int_cert: str, in_issuer_cert: str, in_algo: Algo, issuer_sk: str):
    cert_renew_obj = CertRenew(server_cli)
    tbs_cert = cert_renew_obj.tbs_cert_build(int_cert, in_issuer_cert, in_algo)
    if in_issuer_cert:
        sign_algo = NewUtils.extract_sign_algo(bytes.fromhex(in_issuer_cert))
    else:
        sign_algo = in_algo
    sign_data = await cert_renew_obj.sign(tbs_cert, issuer_sk, sign_algo)
    if sign_data :
        cert_data = cert_renew_obj.cert_build(sign_data, sign_algo)
        return NewUtils.urlsafe_b64encode(cert_data)
