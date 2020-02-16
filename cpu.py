import mem
import struct
import pointer
import modrm_based_instruction

regs64 = {
	"rax": 0,
	"rcx": 1,
	"rdx": 2,
	"rbx": 3,
	"rsp": 4,
	"rbp": 5,
	"rsi": 6,
	"rdi": 7,
	"r8": 8,
	"r9": 9,
	"r10": 10,
	"r11": 11,
	"r12": 12,
	"r13": 13,
	"r14": 14,
	"r15": 15
}

class cpu:
	def __init__(self, mem, rip):
		self.registers = [0xCC] * 16
		self.registers[4] = 0xDEADBEEFDEADBEEF
		self.mem = mem
		self.rip = rip
		self.prefixes = []
		self.flags = {
			"cf": 0,
			"pf": 0,
			"af": 0,
			"zf": 0,
			"sf": 0,
			"tf": 0,
			"if": 0,
			"df": 0,
			"of": 0,
			"iopl": 0,
			"rf": 0,
			"vm": 0,
			"ac": 0,
			"vif": 0,
			"vip": 0,
			"id": 0,
		}

	def get_register(self, name):
		
		if name in regs64:
			return self.registers[regs64[name]]
		
		raise Exception("Unknown register " + name)
	
	def step(self):	

		self.rip_orig = self.rip

		# prefix

		self.prefixes = []	
		prefixes = [0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0x9B, 0xF0, 0xF2, 0xF3]
	
		while True:
			byte = self.pop_byte()
			if byte in prefixes:
				self.prefixes.append(byte)
			else:
				break
	
		# REX prefix
		
		if byte in range(0x40, 0x50):
			self.rex = byte
			byte = self.pop_byte()
		else:
			self.rex = 0x40
			
		rex = self.rex

		rex_w = (rex & 0b00001000) >> 3
		rex_r = (rex & 0b00000100) >> 2
		rex_x = (rex & 0b00000010) >> 1
		rex_b = (rex & 0b00000001)

		# opcode
	
		opcode = byte
		if opcode == 0x0F:
			byte = self.pop_byte()
			if byte in [0x38, 0x3A]:
				opcode = 0x0F * 256 * 256 + byte * 256 + self.pop_byte()
			else:
				opcode = 0x0F * 256 + byte

		print("opcode = " + hex(opcode))

		if ((opcode in range(0, 0x40)) and ((opcode % 8) in [0,1,2,3])) or (opcode in [0x81, 0x83, 0x89, 0x8B, 0xC7]):
			instr = modrm_based_instruction.modrm_based_instruction(self, self.prefixes, self.rex, opcode)
			
		elif opcode in range(0x50, 0x58): # PUSH
			operand_size = 2 if 0x66 in self.prefixes else 8
			reg = rex_r * 8 + opcode - 0x50
			a = self.mk_ptr('r', reg, operand_size)
			b = self.mk_ptr('m', self.registers[4], operand_size)
			b.set(a.get())
			self.registers[4] -= operand_size

		elif opcode in range(0x58, 0x60): # PUSH
			operand_size = 2 if 0x66 in self.prefixes else 8
			reg = rex_r * 8 + opcode - 0x58
			a = self.mk_ptr('r', reg, operand_size)
			b = self.mk_ptr('m', self.registers[4], operand_size)
			a.set(b.get())
			self.registers[4] += operand_size
		
		elif opcode in range(0xB8, 0xC0): # MOV
			operand_size = 8 if rex_w else 2 if 0x66 in self.prefixes else 4
			self.registers[opcode - 0xB8] = self.pop_number(operand_size)
		
		elif opcode == 0x0F05: # SYSCALL
			rax = self.registers[0]
			rdi = self.registers[7]
			rsi = self.registers[6]
			rdx = self.registers[2]
			print("syscall {0} {1} {2} {3}".format(rax, rdi, rsi, rdx))
			rax = self.registers[0]
			if rax == 1: # sys_write
				if rdi == 1: # stdout
					print(self.mem.get_range(rsi, rdx).decode())
			elif rax == 60: # sys_exit
				print("Program finished with status {0}".format(rdi))
				exit(0)
			
		else:
			raise Exception("Unsupported opcode " + hex(opcode))

	def pop_byte(self):
		tmp = self.mem.get_byte(self.rip)
		self.rip += 1
		return tmp

	def pop_number(self, size):
		assert(size in [1,2,4,8])
		fmt = {1: "B", 2: "H", 4: "L", 8: "Q"}[size]
		tmp = struct.unpack("<"+fmt, self.mem.get_range(self.rip, size))[0]
		self.rip += size
		return tmp

	def __str__(self):
		tmp = hex(self.rip)
		for reg in self.registers:
			tmp += " " + hex(reg)
		return tmp
				
	def mk_ptr(self, type, addr, size):
		if type == 'r':
			return pointer.register_pointer(self, addr, size)
		elif type == 'm':
			return pointer.memory_pointer(self.mem, addr, size)
		else:
			raise Exception("Bad ptr: " + addr)
