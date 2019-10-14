import struct
 
class elf_header:
	def __init__(self, bytes):
		self.bytes = bytes
	
		if (bytes[0:4] != bytearray(b"\x7FELF")):
			raise Exception("not ELF")
			
		if bytes[4] != 2:
			raise Exception("only 64 bits supported")
			
		self.little_endian = (bytes[5] == 1)
		
		self.entry = self.__read_field8(0x18)
		
		# size of a program header table entry
		self.e_phentsize = self.__read_field2(0x36)
		self.e_phnum = self.__read_field2(0x38)

		self.e_shentsize = self.__read_field2(0x3A)
		self.e_shnum = self.__read_field2(0x3C)

		self.e_shstrndx = self.__read_field2(0x3E)

		
	def __str__(self):
		return "e_phentsize = " + str(self.e_phentsize) + "\n" + \
			"e_phnum = " + str(self.e_phnum) + "\n" + \
			"e_shentsize = " + str(self.e_phentsize) + "\n" + \
			"e_shnum = " + str(self.e_phnum) + "\n" + \
			"e_shstrndx = " + str(self.e_shstrndx) + "\n"
		
	def __read_field8(self, pos):
		fmt = "<Q" if self.little_endian else ">Q"
		return struct.unpack(fmt, self.bytes[pos:pos + 8])[0]

	def __read_field2(self, pos):
		fmt = "<H" if self.little_endian else ">H"
		return struct.unpack(fmt, self.bytes[pos:pos + 2])[0]
