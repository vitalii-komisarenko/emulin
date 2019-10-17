#!/usr/bin/python3

import struct
import elf_header_parser

#fh = open("calc", "rb")
fh = open("hello", "rb")
 
bytes = bytearray(fh.read())


header = elf_header_parser.elf_header(bytes)

# entry = struct.unpack("<Q", bytes[0x18:0x18 + 8])[0]
entry = header.entry
print(entry)

print(header)

print(list(map(hex, header.mem.mem.keys())))

print(header.cpu)
print("pos = ", hex(header.cpu.rip))
print(list(map(hex, header.mem.get_range(header.cpu.rip,10))))

while True:
	header.cpu.step()
	print(header.cpu)
	print("pos = ", hex(header.cpu.rip))
	print(list(map(hex, header.mem.get_range(header.cpu.rip,10))))
	
	x = input("")