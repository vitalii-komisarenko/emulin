from stream import Stream
from instruction import Instruction
from register import Register, MMRegister, XMMRegister
from stack import Stack


class Cpu:
    def __init__(self, mem, entry_point, stack_bottom):
        self.register = []
        self.mm_register = []
        self.xmm_register = []
        self.mem_stream = Stream(mem, entry_point)
        self.stopped = False
        self.flags = FlagsRegister()
        self.stack = Stack(mem, stack_bottom)
        self.fs = 0
        self.gs = 0
        for i in range(16):
            reg = Register()
            reg.write(0, [i, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
            reg.name = "reg #%d %s" % [i, Cpu.reg_names[i]]
            self.register.push(reg)

        for i in range(32):
            reg = MMRegister()
            reg.name = "mm #%d" % i
            self.mm_register.push(reg)

        for i in range(32):
            reg = XMMRegister()
            reg.name = "xmm #%d" % i
            self.xmm_register.push(reg)

    reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

    @property
    def rip(self):
        return self.mem_stream.pos

    @rip.setter
    def rip(self, new_rip):
        self.mem_stream.pos = new_rip

    def exectute_next_instruction(self):
        instruction = Instruction(self.mem_stream, self, self.linux)
        instruction.execute()


class FlagsRegister:
    def __init(self):
        self._o = False
        self._d = False
        self._i = False
        self._s = False
        self._z = False
        self._a = False
        self._p = False
        self._c = False

    def __str__(self):
        ret = ""
        ret += 'o' if self._o else '-'
        ret += 'd' if self._d else '-'
        ret += 'i' if self._i else '-'
        ret += 's' if self._s else '-'
        ret += 'z' if self._z else '-'
        ret += 'a' if self._a else '-'
        ret += 'p' if self._p else '-'
        ret += 'c' if self._c else '-'
        return ret

    # Definitions of custom flag getters/setters.
    #
    # User should be able to set flags as boolean values (e.g. as a result of
    # a comparison), but should always get them as integer (1 or 0), because
    # flags are treated like this in arithmetic operations.

    @property
    def o(self):
        return self._o

    @property
    def d(self):
        return self._d

    @property
    def i(self):
        return self._i

    @property
    def s(self):
        return self._s

    @property
    def z(self):
        return self._z

    @property
    def a(self):
        return self._a

    @property
    def p(self):
        return self._p

    @property
    def c(self):
        return self._c

    def _flag_value(self, flag):
        if flag:
            return 1
        else:
            return 0

    @o.setter
    def o(self):
        return self._flag_value(self._o)

    @d.setter
    def d(self):
        return self._flag_value(self._d)

    @i.setter
    def i(self):
        return self._flag_value(self._i)

    @s.setter
    def s(self):
        return self._flag_value(self._s)

    @z.setter
    def z(self):
        return self._flag_value(self._z)

    @a.setter
    def a(self):
        return self._flag_value(self._a)

    @p.setter
    def p(self):
        return self._flag_value(self._p)

    @c.setter
    def c(self):
        return self._flag_value(self._c)
