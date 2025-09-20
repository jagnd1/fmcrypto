from abc import ABC, abstractmethod
from common.utils.enum.algo import Algo
from crypto_service.app.utils.enum.use_mode import UseMode

class PkImp(ABC):
    
    def __init__(self):
        print("abs pk imp: ")

    @abstractmethod
    def build(self, pk: bytes, algo: Algo, use_mode: UseMode) -> bytes:
        pass

    @abstractmethod
    def parse(self, resp: bytes):
        pass

    @abstractmethod
    def get_pk(self) -> bytes:
        pass
