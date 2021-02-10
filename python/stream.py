from pointer import Pointer, PointerSigned


class Stream:
    def __init__(self, memory, pos):
        self.mem = memory
        self.pos = pos

    def read(self):
        ret = self.mem.read(self.pos, 1)[0]
        self.pos += 1
        return ret

    def back(self):
        self.pos -= 1

    def read_pointer(self, size):
        res = Pointer(self.mem, self.pos, size)
        self.pos += size
        return res

    def read_signed_pointer(self, size):
        res = PointerSigned(self.mem, self.pos, size)
        self.pos += size
        return res
