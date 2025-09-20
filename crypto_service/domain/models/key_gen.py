from abc import ABC, abstractmethod
from typing import Tuple

from common.utils.enum.algo import Algo
from crypto_service.app.utils.enum.key_type import KeyType
from crypto_service.app.utils.enum.use_mode import UseMode


class KeyGen(ABC):
    
    def __init__(self):
        print("abs key gen: ")

    @abstractmethod
    def build(
        self, in_key_type: KeyType, in_use_mode: UseMode, in_exp_key: bytes, 
        in_algo: Algo) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_key(self) -> Tuple[bytes, bytes]:
        pass
