from pointer import Pointer


class Stack:
    def __init__(self, mem, stack_buttom):
        self.mem = mem
        self.pos = stack_buttom

    def push(self, data):
        self.pos -= len(data)
        Pointer(self.mem, self.pos, len(data)).write(data)

    def pop(self, size):
        ret = Pointer(self.mem, self.pos, size).read()
        self.pos += size
        return ret
