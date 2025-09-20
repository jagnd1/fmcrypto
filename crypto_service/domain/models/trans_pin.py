from abc import ABC, abstractmethod

class TransPin(ABC):
    
    def __init__(self):
        print("abs trans pin: ")

    @abstractmethod
    def build(
        self, key: bytes, dest_key: bytes, ksn: bytes, src_pinblk: bytes, pan: bytes, 
        dest_ksn: bytes) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_pinblk(self) -> bytes:
        pass
