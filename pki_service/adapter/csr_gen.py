import asyncio
from typing import Union

import httpx

from common.utils.enum.algo import Algo
from common.utils.crypto import Utils as NewUtils
from pki_service.adapter.base.csr_gen import CsrGen as BaseCsrGen
from pki_service.adapter.server_cli import ServerCli, crypto_hsm
"""
verify using below command:
openssl req -text -verify -in csr.pem

where: csr.pem should look like this

-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----
"""

class CsrGen(BaseCsrGen):

    def __init__(self, server_cli: ServerCli):
        super().__init__()
        self.server_cli = server_cli
        print("csr gen: ")
            
    async def _gen_key(self, in_algo: Algo):
        # prepare the request parameters
        ep: str = f"kp_gen?hsm_name={crypto_hsm}"
        data = {
            "algo": Algo.get_algo_str(in_algo),
            "use_mode": "SIGN"
        }
        # send the req
        resp = await self.server_cli.exchange(ep, data)
        if resp and resp['status'] == "success":
            # parse the resp
            _pk = NewUtils.urlsafe_b64decode(resp['pk'].encode())
            print(f"pk: {_pk.hex()}")
            self.pk_obj = NewUtils.deserialize_pk(_pk)
            self.sk_lmk = resp['sk_lmk']
            print(f"sk_lmk: {self.sk_lmk}")
            return resp

    async def sign(self, data: bytes, in_algo: Algo) -> Union[bytes, None]:
        ep: str = f"gen_sign?hsm_name={crypto_hsm}"
        data = {
            "msg": f"{data.hex()}",
            "sk_lmk": f"{self.sk_lmk}",
            "algo": f"{Algo.get_algo_str(in_algo)}",
        }
        resp = await self.server_cli.exchange(ep, data)
        if resp and resp['status'] == "success":
            self.sign_data = bytes.fromhex(resp['signature'])
            return self.sign_data
    
    def get_kp(self):
        return self.pk_obj, self.sk_lmk
        
async def csr_gen(server_cli: ServerCli, in_algo: str, in_sub: dict[str, str]):
    csr_gen_obj = CsrGen(server_cli)
    algo = Algo.get_str_algo(in_algo)
    resp = await csr_gen_obj._gen_key(algo)
    if resp:
        cert_req_info = csr_gen_obj.cert_req_info_build(in_sub, algo)
        _ = await csr_gen_obj.sign(cert_req_info, algo)
        csr_data = csr_gen_obj.cert_req_build(algo)
        print(f"csr hex: {csr_data.hex()}")
        print (f"csr b64 ue: {NewUtils.urlsafe_b64encode(csr_data)}")
        return NewUtils.urlsafe_b64encode(csr_data), csr_gen_obj.pk_obj, csr_gen_obj.sk_lmk

