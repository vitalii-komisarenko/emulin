require_relative "elf_parser"

elf = Elf.new("../hello_c-static")

puts "is 64 bit: %s" % elf.elf_header.is_64_bit
