require_relative "elf_parser"
require_relative "memory"
require_relative "cpu"

elf = Elf.new("../hello")

puts "is 64 bit: %s" % elf.elf_header.is_64_bit

mem = Memory.new

# Load program segments into the memory
elf.program_header.entries.each do |ph|
	puts "writing a segment: %d bytes at position 0x%x" % [ph.data_to_load_to_memory.length, ph.p_vaddr]
	mem.write(ph.p_vaddr, ph.data_to_load_to_memory)
end

cpu = Cpu.new(mem, elf.elf_header.e_entry)
while true
	cpu.exectute_next_instruction
end