from abc import ABC, abstractmethod

from common.utils.enum.encr_mode import EncrMode
from common.utils.enum.algo import Algo

class DataEncr(ABC):
    
    def __init__(self):
        print("abs data encr: ")

    @abstractmethod
    def build(
        self, msg: bytes, key: bytes, encr_mode: EncrMode, iv: str, ksn: bytes, 
        algo: Algo) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_msg(self) -> bytes:
        pass
