class eflags:
	__flag_name_to_bit_index = {
		'CF': 0, 'PF': 2, 'AF': 4, 'ZF': 6, 'SF': 7, 'OF': 11
	}

	def __init__(self):
		self.reg = 0x00000002
		
	def __set_bit(self, pos, bit):
		self.reg = (self.reg & (~(1 << pos))) | (bit << pos)

	def __get_bit(self, pos):
		return self.reg & (1 << pos)
		
	def __flag_name_to_index(name):
		n = name.upper()
		if (n in eflags.__flag_name_to_bit_index):
			return eflags.__flag_name_to_bit_index[n]
		else:
			raise Exception("No such flag: " + name)
		
	def set_flag(self, name, value):
		pos = eflags.__flag_name_to_index(name)
		self.__set_bit(pos, value)
		
	def get_flag(self, name):
		pos = __flag_name_to_index(name)
		return self.__get_bit(pos)

	def set_flags_for_value(self, value, size, mask):
		flags = list(mask)
		for f in flags:
			if f == 'c':
				# TODO
				pass
			elif f == 'p':
				v1 = value & 1
				v2 = value & (1 << 1)
				v3 = value & (1 << 2)
				v4 = value & (1 << 3)
				v5 = value & (1 << 4)
				v6 = value & (1 << 5)
				v7 = value & (1 << 6)
				v8 = value & (1 << 7)
				flag_value = (1 + v1 + v2 + v3 + v4 + v5 + v6 + v7 + v8) % 2
				self.set_flag('PF', flag_value)
			elif f == 'a':
				# TODO
				pass
			elif f == 'z':
				flag_value = 1 if value == 0 else 1
				self.set_flag('ZF', flag_value)
			elif f == 's':
				pos = size * 8 - 1
				flag_value = value & (1 << pos)
				self.set_flag('SF', flag_value)
			elif f == 'o':
				# TODO
				pass
			else:
				raise Exception("Unsupported flag: " + f)