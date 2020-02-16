from abc import ABC, abstractmethod
import struct

class pointer(ABC):
	@abstractmethod
	def get_value_8_bytes(self):
		pass

	@abstractmethod
	def set_value_8_bytes(self, value):
		pass
		
	def get_size(self):
		return self.size
	
	def get(self):
		return self.get_value_8_bytes() % (256 ** self.size)
		
	def set(self, value):
		old_value = self.get_value_8_bytes()
		new_value = old_value - (old_value % (256 ** self.size)) + (value % (256 ** self.size))
		self.set_value_8_bytes(new_value)
		
class register_pointer(pointer):
	def __init__(self, cpu, reg, size):
		self.cpu = cpu
		self.reg = reg
		self.size = size
	
	def get_value_8_bytes(self):
		return self.cpu.registers[self.reg]
	
	def set_value_8_bytes(self, value):
		self.cpu.registers[self.reg] = value
	
	def __str__(self):
		return "reg #" + str(self.reg) + " " + str(self.size) + " bytes"
	
class memory_pointer(pointer):
	def __init__(self, mem, addr, size):
		self.mem = mem
		self.addr = addr
		self.size = size

	def get_value_8_bytes(self):
		return struct.unpack("<Q", self.mem.get_range(self.addr, self.size))[0]
	
	def set_value_8_bytes(self, value):
		self.mem.set_range(self.addr, struct.pack("<Q", value))
		
	def __str__(self):
		return "memory at " + hex(self.addr) + " " + self.size + " bytes"
		
class immediate_pointer(pointer):
	def __init__(self, imm, size):
		self.imm = imm
		self.size = size
		
	def get_value_8_bytes(self):
		return self.imm
		
	def set_value_8_bytes(self, value):
		self.imm = value
		
	def __str__(self):
		return "variable " + str(self.size) + " bytes"