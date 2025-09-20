import os
from crypto_service.adapter.gp.models import GPHSM

hsm_name = os.getenv("CRYPTO_HSM", "GP")

class HSMService:
    
    def __init__(self, hsm_name: str = "GP"):
        self.hsm_name = hsm_name

    def __call__(self, hsm_name: str = "GP"):
        if hsm_name == "GP":
            return GPHSM()
        else:
            raise NotImplementedError("invalid hsm name")

