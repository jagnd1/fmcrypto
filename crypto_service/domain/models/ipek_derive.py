from abc import ABC, abstractmethod
from typing import Tuple

from common.utils.enum.algo import Algo
from crypto_service.app.utils.enum.use_mode import UseMode

class IpekDerive(ABC):
    
    def __init__(self):
        print("abs ipek derive: ")

    @abstractmethod
    def build(
        self, bdk: bytes, iksn: bytes, tk: bytes, in_algo: Algo, in_use_mode: UseMode) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_key(self) -> Tuple[bytes, bytes, bytes]:
        pass
