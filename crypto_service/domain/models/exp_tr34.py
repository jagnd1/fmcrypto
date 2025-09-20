from abc import ABC, abstractmethod
from typing import Tuple

class ExpTr34(ABC):
    
    def __init__(self):
        print("abs exp tr34: ")

    @abstractmethod
    def build(
        self, kbpk: bytes, kcv: bytes, kdh_cert: bytes, krd_cert: bytes, kdh_sk: bytes) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_tr34(self) -> Tuple[bytes, bytes, bytes]:
        pass
