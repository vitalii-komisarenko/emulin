from addressable import Addressable


class Memory(Addressable):
    def __init__(self):
        super().__init__()
        self.name = "memory"
