#!/usr/bin/python3

import struct
import elf_header_parser

fh = open("calc", "rb")
 
bytes = bytearray(fh.read())


header = elf_header_parser.elf_header(bytes)

# entry = struct.unpack("<Q", bytes[0x18:0x18 + 8])[0]
entry = header.entry
print(entry)

pos = entry

print(header)

while True:
	print("pos = ", hex(pos))
	print(list(map(hex, bytes[pos:pos+10])))
	
	x = input("")