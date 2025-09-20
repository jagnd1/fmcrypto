from enum import Enum, auto

class EncrMode(Enum):
    
    ECB=auto()
    CBC=auto()
    CBC_PAD=auto()
    GCM=auto()

    @staticmethod
    def get_encr_mode(in_encr_mode):
        if in_encr_mode == EncrMode.ECB:
            ret = "00"
        elif in_encr_mode == EncrMode.CBC:
            ret = "01"
        elif in_encr_mode == EncrMode.GCM:
            ret = "02"
        return ret
    
    @staticmethod
    def get_str_encr_mode(in_encr_mode):
        if in_encr_mode == "ECB":
            return EncrMode.ECB
        elif in_encr_mode == "CBC":
            return EncrMode.CBC
        elif in_encr_mode == "GCM":
            return EncrMode.GCM
        else:
            return EncrMode.CBC
