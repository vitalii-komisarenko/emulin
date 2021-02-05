from stream import Stream
from instruction import Instruction
from register import Register
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
			reg.name = "reg #%d %s" % [i, reg_names[i]]
			self.register.push(reg)

		for i in range(32):
			reg = MMRegister()
			reg.name = "mm #%d" % i
			self.mm_register.push(reg)
		end

		for i in range(32):
			reg = XMMRegister()
			reg.name = "xmm #%d" % i
			self.xmm_register.push(reg)

	reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

	def rip(self):
		return self.mem_stream.pos

	def rip=(new_rip)
		@mem_stream.pos = new_rip
	end
	
	def exectute_next_instruction(self):
		instruction = Instruction(self.mem_stream, self, self.linux)
		instruction.execute()

class FlagsRegister:
	def initialize
		o = False
		d = False
		i = False
		s = False
		z = False
		a = False
		p = False
		c = False

	def __str__(self):
		ret = ""
		ret += 'o' if self.o else '-'
		ret += 'd' if self.d else '-'
		ret += 'i' if self.i else '-'
		ret += 's' if self.s else '-'
		ret += 'z' if self.z else '-'
		ret += 'a' if self.a else '-'
		ret += 'p' if self.p else '-'
		ret += 'c' if self.c else '-'
		return ret
