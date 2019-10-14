import struct


class program_header:
	def __init__(self, bytes, little_endian):
		self.bytes = bytes
		self.little_endian = little_endian
		self.p_type = read_field4(bytes, little_endian, 0)
		self.p_flags = read_field4(bytes, little_endian, 4)
		self.p_offset = read_field8(bytes, little_endian, 8)
		self.p_vaddr = read_field8(bytes, little_endian, 0x10)
		self.p_paddr = read_field8(bytes, little_endian, 0x18)
		self.p_filesz = read_field8(bytes, little_endian, 0x20)
		self.p_memsz = read_field8(bytes, little_endian, 0x28)
		self.p_align = read_field8(bytes, little_endian, 0x30)
 
class elf_header:
	def __init__(self, bytes):
		self.bytes = bytes
	
		if (bytes[0:4] != bytearray(b"\x7FELF")):
			raise Exception("not ELF")
			
		if bytes[4] != 2:
			raise Exception("only 64 bits supported")
			
		self.little_endian = (bytes[5] == 1)
		
		self.entry = self.__read_field8(0x18)
		
		self.e_phoff = self.__read_field8(0x20)
		
		# size of a program header table entry
		self.e_phentsize = self.__read_field2(0x36)
		self.e_phnum = self.__read_field2(0x38)

		self.e_shentsize = self.__read_field2(0x3A)
		self.e_shnum = self.__read_field2(0x3C)

		self.e_shstrndx = self.__read_field2(0x3E)
		
		self.program_headers = []
		
		for i in range(self.e_phnum):
			b = bytes[self.e_phoff + i * self.e_phentsize: self.e_phoff + (i+1) * self.e_phentsize]
			self.program_headers.append(program_header(b, self.little_endian))
		
		PT_LOAD = 1
		#                      1 2 3 4 5 6 7 8
		self.base_address = 0xFFFFFFFFFFFFFFFF
		for ph in self.program_headers:
			if ph.p_type == PT_LOAD:
				# skip truncating to memory page size
				self.base_address = min(self.base_address, ph.p_vaddr)
		
	def __str__(self):
		return "e_phentsize = " + str(self.e_phentsize) + "\n" + \
			"e_phnum = " + str(self.e_phnum) + "\n" + \
			"e_shentsize = " + str(self.e_phentsize) + "\n" + \
			"e_shnum = " + str(self.e_phnum) + "\n" + \
			"e_shstrndx = " + str(self.e_shstrndx) + "\n" + \
			"base_address = " + hex(self.base_address)
		
	def __read_field8(self, pos):
		fmt = "<Q" if self.little_endian else ">Q"
		return struct.unpack(fmt, self.bytes[pos:pos + 8])[0]

	def __read_field4(self, pos):
		fmt = "<I" if self.little_endian else ">I"
		return struct.unpack(fmt, self.bytes[pos:pos + 4])[0]

	def __read_field2(self, pos):
		fmt = "<H" if self.little_endian else ">H"
		return struct.unpack(fmt, self.bytes[pos:pos + 2])[0]

def read_field8(bytes, little_endian, pos):
	fmt = "<Q" if little_endian else ">Q"
	return struct.unpack(fmt, bytes[pos:pos + 8])[0]

def read_field4(bytes, little_endian, pos):
	fmt = "<I" if little_endian else ">I"
	return struct.unpack(fmt, bytes[pos:pos + 4])[0]

def read_field2(bytes, little_endian, pos):
	fmt = "<H" if little_endian else ">H"
	return struct.unpack(fmt, bytes[pos:pos + 2])[0]
