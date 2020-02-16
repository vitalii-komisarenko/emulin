import pointer

class modrm_based_instruction:
	def __init__(self, cpu, prefixes, rex, opcode):
		self.cpu = cpu
		self.prefixes = prefixes
		self.rex = rex
		self.opcode = opcode

		self.rex_w = (self.rex & 0b00001000) >> 3
		self.rex_r = (self.rex & 0b00000100) >> 2
		self.rex_x = (self.rex & 0b00000010) >> 1
		self.rex_b = (self.rex & 0b00000001)
		
		self.mod_reg_rm = self.cpu.pop_byte()
		self.modrm_mode = (self.mod_reg_rm & 0b11000000) >> 6
		modrm_reg  = (self.mod_reg_rm & 0b00111000) >> 3
		self.modrm_rm   = (self.mod_reg_rm & 0b00000111)

		if self.has_opcode_extension():
			self.modrm_reg = None
			self.opcode_ext = modrm_reg
		else:
			self.modrm_reg = modrm_reg
			self.opcode_ext = None

		self.sib = None

		if (self.modrm_mode in [0, 1, 2]) and (self.modrm_rm == 0b100):
			self.sib = self.cpu.pop_byte()
		
		displacement_size = {
			0: 4 * (self.modrm_rm == 0b101),
			1: 1,
			2: 4,
			3: 0
		} [self.modrm_mode]
			
		displacement = 0 if displacement_size == 0 else self.cpu.pop_number(displacement_size)

		a = None if self.has_opcode_extension() else self.cpu.mk_ptr('r', 8 * self.rex_r + self.modrm_reg, self.operand_size())

		if self.sib != None:
			raise Exception("Not implemented")
		else:
			if self.modrm_mode == 0b11:
				b = self.cpu.mk_ptr('r', 8 * self.rex_b + self.modrm_rm, self.operand_size())
			elif (self.modrm_mode == 0) and (self.modrm_rm == 0b101):
				b = self.cpu.mk_ptr('m', self.rip % (256 ** self.address_size()) + displacement, self.operand_size())
			else:
				b = self.cpu.mk_ptr('m', self.cpu.registers[8 * self.rex_b + self.modrm_rm] % (256 ** self.address_size()), self.operand_size())

		imm_size = self.immediate_size()
		imm = None if imm_size == 0 else self.cpu.pop_number(imm_size)

		if imm == None:
			if self.direction:
				args = (b, a)
			else:
				args = (a, b)
		else:
			args = (b, pointer.immediate_pointer(imm, imm_size))
		
		print(hex(self.opcode), self.function(), args[0], args[1])
		
		modrm_based_instruction.apply_function(self.function(), args[0], args[1], self.cpu)

	def immediate_size(self):
		if self.opcode in range(0x00, 0x40):
			return [0, 0, 0, 0, 1, "TODO"][self.opcode & 0b111]
		elif self.opcode == 0x83:
			return 1
		elif self.opcode in [0xB8, 0xC7]:
			return self.operand_size()
		elif self.opcode in [0x89]:
			return 0

		raise Exception("Unknown immediate size for opcode " + hex(self.opcode))
			
	def operand_size(self):
		if self.opcode in range(0, 0x40):
			if (self.opcode % 8) in [1, 3]:
				return 8 if self.rex_w else 2 if 0x66 in self.prefixes else 4
			if (self.opcode % 8) in [0, 2]:
				return 1
		elif self.opcode in [0x81, 0x83, 0xB8, 0x89, 0xC7]:
			return 8 if self.rex_w else 2 if 0x66 in self.prefixes else 4

		raise Exception("Unknown operand size for opcode " + hex(self.opcode))

	def address_size(self):
		if self.opcode in (0, 0x40):
			if (self.opcode % 8) in [0, 1, 2, 3]:
				return 4 if 0x67 in self.prefixes else 8
				
		if self.opcode in [0xB8]:
			return 4 if 0x67 in self.prefixes else 8

		raise Exception("Unknown address size for opcode " + hex(self.opcode))

	def has_opcode_extension(self):
		if self.opcode in [0x80, 0x81, 0x83, 0x8F, 0xC0, 0xC1, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3]:
			return True
		elif self.opcode in range(0xD8, 0xE0):
			return True
		elif self.opcode in [0xF6, 0xF7, 0xFE, 0xFF]:
			return True
		elif self.opcode in [0x0F00, 0x0F01, 0x0F18, 0x0F1F, 0x0F71, 0x0F72, 0x0F73]:
			return True
		elif self.opcode in range(0x0F90, 0x0FA0):
			return True
		elif self.opcode in [0x0FAE, 0x0FBA, 0x0FC7]:
			return True
		else:
			return False
	
	def apply_function(f, a, b, cpu):
		# TODO: flags
		res = 0
		if f == 'add':
			res = a.get() + b.get()
		elif f == 'or':
			res = a.get() | b.get()
		elif f == 'adc':
			res = a.get() + b.get()
		elif f == 'sbb':
			res = a.get() - b.get() - cpu.flags['cf']
		elif f == 'and':
			res = a.get() & b.get()
		elif f == 'sub':
			res = a.get() - b.get()
		elif f == 'xor':
			res = a.get() ^ b.get()
		elif f == 'mov':
			a.set(b.get())
			return
		else:
			raise Exception("Bad function: " + f)
			
		a.set(res)
		cpu.flags['zf'] = 1 if res == 0 else 0
		cpu.flags['sf'] = (res >> (a.get_size() - 1)) & 1
		cpu.flags['pf'] = res & 1
			
	def function(self):
		if self.opcode in range(0x00, 0x40):
			return ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp'][self.opcode >> 3]
		
		if self.opcode in [0x80, 0x81, 0x83]:
			return ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp'][self.opcode_ext]
		
		if self.opcode in range(0xB0, 0xC0):
			return 'mov'
		
		if self.opcode in [0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8E, 0xC7]: # 0x8D = LEA
			return 'mov'
		
		raise Exception("No function for opcode " + hex(self.opcode))
		
	def direction(self): # TODO
		if self.opcode in [0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31, 0x39, 0x89]:
			return 1
		else:
			return 0
