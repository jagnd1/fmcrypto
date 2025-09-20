from abc import ABC, abstractmethod

class ExpKey(ABC):
    
    def __init__(self):
        print("abs exp key: ")

    @abstractmethod
    def build(self, key: bytes, kcv: bytes, pk: bytes) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_enc_key(self) -> bytes:
        pass
