from abc import abstractmethod

class Client():

    def __init__(self):
        print("model client init")

    @abstractmethod
    def add_header_len(self, req: bytes) -> bytes:
        pass

    @abstractmethod
    def remove_header_len(self, resp: bytes) -> bytes:
        pass

    @abstractmethod
    def exec(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def close(self):
        pass
