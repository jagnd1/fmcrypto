    
import logging
import os
import httpx

from common.middlewares.reqid_exception import AdapterException

protocol = os.getenv("PROTOCOL", "http")
crypto_host = os.getenv("CRYPTO_HOST", "localhost")
crypto_port = os.getenv("CRYPTO_PORT", "8001")
crypto_hsm = os.getenv("CRYPTO_HSM", "GP")
service_name = "crypto"

crypto_url = f"{protocol}://{crypto_host}:{crypto_port}/v1/{service_name}/"
client = httpx.AsyncClient(timeout=None)

logger = logging.getLogger(__name__)

def get_client():
    return client

async def close_client():
    await client.aclose()

class ServerCli():
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def exchange(self, ep: str, req: dict):
        url = crypto_url + ep
        logger.info(f"url: {url}")
        print(f"url: {url}")
        logger.info(f"req: {req}")
        print(f"req: {req}")
        try:
            resp = await self.client.post(url, json=req)
            resp.raise_for_status()
            logger.info(f"resp: {resp.text}")
            return resp.json()
        except httpx.HTTPStatusError as e:
            try:
                error_detail = e.response.json().get("detail", "no detailed error!")
                raise AdapterException(error_detail)
            except Exception as e:
                raise AdapterException(f"{str(e)}")
        except Exception as e:
            raise AdapterException(f"{str(e)}")
        
