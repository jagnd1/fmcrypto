from abc import ABC, abstractmethod
from typing import Tuple

from common.utils.enum.algo import Algo
from crypto_service.app.utils.enum.use_mode import UseMode


class KpGen(ABC):
    
    def __init__(self):
        print("abs kp gen: ")
        self.pk = b''
        self.sk_lmk = b''

    @abstractmethod
    def build(self, in_algo: Algo, in_use_mode: UseMode) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_kp(self) -> Tuple[bytes, bytes]:
        pass
