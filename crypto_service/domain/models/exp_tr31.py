from abc import ABC, abstractmethod
from typing import Tuple

class ExpTr31(ABC):
    
    def __init__(self):
        print("abs exp key: ")
    
    @abstractmethod
    def build(self, exp_key: bytes, key: bytes, iksn: bytes) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes) -> None:
        pass

    @abstractmethod
    def get_key(self) -> Tuple[bytes, bytes]:
        pass
