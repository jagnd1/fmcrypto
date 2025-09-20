from abc import ABC, abstractmethod
from typing import Any

from common.utils.enum.algo import Algo
from crypto_service.app.utils.enum.key_type import KeyType
from crypto_service.app.utils.enum.use_mode import UseMode


class Ecdh(ABC):
    
    def __init__(self):
        print("abs ecdh: ")

    @abstractmethod
    def build_recp_derive_shared(
        self, in_algo: Algo, eph_pk: bytes, shared_info: bytes, key_type: KeyType, 
        in_use_mode: UseMode) -> bytes:
        pass

    @abstractmethod
    def parse_recp_derive_shared(self, resp: bytes):
        pass

    @abstractmethod
    def get_recp_derive(self) -> Any:
        pass
