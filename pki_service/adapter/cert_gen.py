from typing import Union
from common.middlewares.reqid_exception import BusinessLogicException
from common.utils.enum.algo import Algo
from common.utils.enum.cert_level import CertLevel
from common.utils.crypto import Utils as NewUtils
from pki_service.adapter.base.cert_gen import CertGen as BaseCertGen
from pki_service.adapter.server_cli import ServerCli

"""
verify cert using below command:
openssl x509 -in cert.pem -text -noout

verify cert chain:
openssl verify -untrusted <intermediary-certificate> <certificate>

where as cert.pem should look like this
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""

"""
verify self signed cert
openssl verify -CAfile selfsigned.pem selfsigned.pem
"""

from pki_service.adapter.server_cli import crypto_hsm

class CertGen(BaseCertGen):

    def __init__(self, server_cli: ServerCli):
        self.server_cli = server_cli
        print("cert gen:")

    async def sign(self, data: bytes, sk_lmk: str, algo: Algo):
        ep: str = f"gen_sign?hsm_name={crypto_hsm}"
        data = {
            "msg": f"{data.hex()}", "sk_lmk": f"{sk_lmk}", "algo": f"{Algo.get_algo_str(algo)}",}
        resp = await self.server_cli.exchange(ep, data)
        if resp and resp['status'] == "success":
            self.sign_data = bytes.fromhex(resp['signature'])
            return self.sign_data


async def cert_gen(server_cli: ServerCli, csr: str, issuer_sk: str, cert_level: CertLevel, algo: Algo, 
                   issuer_cert: str = None) -> Union[str, None]:
    cert_gen_obj = CertGen(server_cli)
    if issuer_cert:
        sign_algo = NewUtils.extract_sign_algo(bytes.fromhex(issuer_cert))
    else:
        sign_algo = algo
    tbs_cert = cert_gen_obj.tbs_cert_build(csr, algo, cert_level, issuer_cert)
    sign_data = await cert_gen_obj.sign(tbs_cert, issuer_sk, sign_algo)
    if sign_data:
        cert_data = cert_gen_obj.cert_build(sign_data, sign_algo)
        return NewUtils.urlsafe_b64encode(cert_data)
