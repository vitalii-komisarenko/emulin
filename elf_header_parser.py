import struct
import mem
import cpu

class program_header:
	def __init__(self, bytes):
		self.bytes = bytes
		
		self.p_type, \
		self.p_flags, \
		self.p_offset, \
		self.p_vaddr, \
		self.p_paddr, \
		self.p_filesz, \
		self.p_memsz, \
		self.p_align = struct.unpack("<LLQQQQQQ", bytes)

class section_header:
	def __init__(self, bytes):
		self.bytes = bytes
	
		self.sh_name, \
		self.sh_type, \
		self.sh_flags, \
		self.sh_addr, \
		self.sh_offset, \
		self.sh_size, \
		self.sh_link, \
		self.sh_info, \
		self.sh_addralign, \
		self.sh_entsize = struct.unpack("<LLQQQQLLQQ", bytes)

	def __str__(self):
		return "name={0:<20} addr={1:0>8x} offset={2:0>8x} size={3:0>8x}".format(self.name, self.sh_addr, self.sh_offset, self.sh_size)

def c_string(bytes, pos):
	res = bytearray()
	while True:
		if bytes[pos] == 0:
			return res.decode()
		else:
			res.append(bytes[pos])
			pos = pos + 1

class elf_header:
	def __init__(self, bytes):
		self.bytes = bytes
	
		if bytes[0:4] != bytearray(b"\x7FELF"):
			raise Exception("not ELF")
			
		if bytes[4] != 2:
			raise Exception("only 64 bits supported")
		
		if bytes[5] != 1:
			raise Exception("x86_64 must be little endian")

		self.e_type, \
		self.e_machine, \
		self.e_version, \
		self.e_entry, \
		self.e_phoff, \
		self.e_shoff, \
		self.e_flags, \
		self.e_ehsize, \
		self.e_phentsize, \
		self.e_phnum, \
		self.e_shentsize, \
		self.e_shnum, \
		self.e_shstrndx = struct.unpack("<HHLQQQL6H", bytes[0x10:0x40])

		self.entry = self.e_entry
		
		self.program_headers = []
		
		for i in range(self.e_phnum):
			b = bytes[self.e_phoff + i * self.e_phentsize: self.e_phoff + (i+1) * self.e_phentsize]
			self.program_headers.append(program_header(b))

		for ph in self.program_headers:
			print("program header: " + hex(ph.p_type))
		
		self.mem = mem.mem()
		
		#                      1 2 3 4 5 6 7 8
		self.base_address = 0xFFFFFFFFFFFFFFFF
		for ph in self.program_headers:
			if ph.p_type == 1: # PT_LOAD
				# skip truncating to memory page size
				self.base_address = min(self.base_address, ph.p_vaddr)
				
				self.mem.set_range(ph.p_vaddr, ph.bytes)

			elif ph.p_type == 4: # PT_NOTE
				pass
			elif ph.p_type == 7: # PT_TLS / thread-local storage
				pass
			elif ph.p_type == 0x6474e551: # PT_GNU_STACK
				# seems to do smth with the stack permissions
				pass
			elif ph.p_type == 0x6474e552: # PT_GNU_RELRO
				# the array element specifies the location and size of a segment which may be made read-only after relocations have been processed.
				pass
			else:
				raise Exception("Unsupported program header type: " + hex(ph.p_type))
				
		self.section_headers = []

		for i in range(self.e_shnum):
			b = bytes[self.e_shoff + i * self.e_shentsize: self.e_shoff + (i+1) * self.e_shentsize]
			self.section_headers.append(section_header(b))
			
		for sh in self.section_headers:
			sh.name = c_string(bytes, self.section_headers[self.e_shstrndx].sh_offset + sh.sh_name)

		# Loading sections to memory
		for sh in self.section_headers:
			if sh.sh_type == 0: # SHT_NULL
				pass
			elif sh.sh_flags and 0x2: #SHF_ALLOC
				pass
				self.mem.set_range(sh.sh_addr, bytes[sh.sh_offset:sh.sh_offset+sh.sh_size])
				
		self.cpu = cpu.cpu(self.mem, self.entry)

	def __str__(self):
		tmp = "e_phentsize = " + str(self.e_phentsize) + "\n" + \
			"e_phnum = " + str(self.e_phnum) + "\n" + \
			"e_shentsize = " + str(self.e_phentsize) + "\n" + \
			"e_shnum = " + str(self.e_phnum) + "\n" + \
			"e_shstrndx = " + str(self.e_shstrndx) + "\n" + \
			"base_address = " + hex(self.base_address) + "\n" + \
			"entry = " + hex(self.entry)
		
		for sh in self.section_headers:
			tmp += "\n{0}".format(sh)
			
		return tmp
		
	def get_section_by_name(self, name):
		for sh in self.section_headers:
			if sh.name == name:
				return sh
				
		raise Exception("No section with name " + name)