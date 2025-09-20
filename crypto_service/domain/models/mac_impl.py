from abc import ABC, abstractmethod
from crypto_service.app.utils.enum.mac_mode import MacMode

class MacImpl(ABC):
    
    def __init__(self):
        print("abs mac impl: ")

    @abstractmethod
    def build(self, key: bytes, ksn: bytes, in_mac_mode: MacMode, mac: bytes, msg: bytes) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_mac(self) -> bytes:
        pass
