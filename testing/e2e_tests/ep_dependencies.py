import os
import httpx
from typing import Any, Dict

hsm_name = os.getenv("CRYPTO_HSM", "GP")
crypto_url = "http://localhost:8001"
pki_url = "http://localhost:8000"
query_param = f"?hsm_name={hsm_name}"

async def exchange(url: str, body: Dict[str, Any], method: str = "POST"):
    async with httpx.AsyncClient(timeout=None) as client:
        req = client.build_request(method=method, url=url, json=body)
        print(f"req url: {req.url}")
        print(f"req method: {req.method}")
        for header, value in req.headers.items():
            print(f"  {header}: {value}")
        print(f"req content: {req.content.decode()}")    
        resp = await client.send(req)
        print(f"resp: {resp.status_code} {resp.json()}")
        if resp.status_code == httpx.codes.OK:
            return resp.json()
        else:
            return None