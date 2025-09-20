from abc import ABC, abstractmethod

class KcvGen(ABC):
    
    def __init__(self):
        print("abs kcv gen: ")

    @abstractmethod
    def build(self, in_key: bytes) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_kcv(self) -> bytes:
        pass
