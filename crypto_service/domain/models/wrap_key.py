from abc import ABC, abstractmethod

from common.utils.enum.algo import Algo

class WrapKey(ABC):
    
    def __init__(self):
        print("abs wrap key: ")

    @abstractmethod
    def build(self, algo: Algo, header: str, kbpk: bytes, key: bytes):
        pass

    @abstractmethod
    def parse(self, resp: str):
        pass

    @abstractmethod
    def get_key(self) -> str:
        pass
