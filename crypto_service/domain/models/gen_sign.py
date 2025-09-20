from abc import ABC, abstractmethod

from common.utils.enum.algo import Algo


class GenSign(ABC):
    
    def __init__(self):
        print("abs gen sign: ")

    @abstractmethod
    def build(self, in_sign_algo: Algo, msg: bytes, sk_lmk: bytes) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass
    
    @abstractmethod
    def get_sign_data(self) -> bytes:
        pass
