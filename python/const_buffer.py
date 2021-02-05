from addressable import Addressable
from pointer import Pointer


class ConstBuffer(Addressable):
    def __init__(self, value, size=8):
        self.in_init = True
        self.size = size
        super().__init__(value, size)
        Pointer(self, 0, size).write_int(value)
        self.name = "const"
        self.in_init = False

    def write(self, pos, data):
        if not self.in_init:
            raise RuntimeError("buffer is read-only")
        super().write(pos, data)

    def ptr(self):
        return Pointer(self, 0, self.size)
