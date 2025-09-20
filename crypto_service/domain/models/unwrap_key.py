from abc import ABC, abstractmethod

class UnwrapKey(ABC):
    
    def __init__(self):
        print("abs unwrap key: ")

    @abstractmethod
    def build(self, kbpk: bytes, key: str):
        pass

    @abstractmethod
    def parse(self, resp: str):
        pass

    @abstractmethod
    def get_key(self) -> str:
        pass
