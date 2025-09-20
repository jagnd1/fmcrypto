from abc import ABC, abstractmethod

from common.utils.enum.algo import Algo
from common.utils.enum.encr_mode import EncrMode

class DataDecr(ABC):
    
    def __init__(self):
        print("abs data decr: ")

    @abstractmethod
    def build(
        self, key: bytes, iv: str, enc_msg: bytes, encr_mode: EncrMode, ksn: bytes, 
        algo: Algo) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_msg(self) -> bytes:
        pass
