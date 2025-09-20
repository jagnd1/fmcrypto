from crypto_service.domain.models.client import Client

class GPClient(Client):

    def __init__(self):
        super().__init__()
        print("gp client")

    def add_header_len(self, req: bytes) -> bytes:
        """dummy for gp hsm"""
        pass

    def remove_header_len(self, resp: bytes) -> bytes:
        """dummy for gp hsm"""
        pass

    def exec(self, data: bytes) -> bytes:
        """dummy for gp hsm"""
        return b""

    async def close(self):
        """dummy for gp hsm"""
        pass

    async def check(self, interval: int=300):
        """dummy for gp hsm"""
        pass
