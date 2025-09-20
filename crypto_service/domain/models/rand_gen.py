from abc import ABC, abstractmethod

class RandGen(ABC):
    
    def __init__(self):
        print("abs rand gen: ")

    @abstractmethod
    def build(self, in_len: int) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_random_no(self) -> bytes:
        pass
