from elf_parser import Elf
from memory import Memory
from cpu import Cpu
from linux import Linux
import traceback


elf = Elf("../progs_to_test/bin/hello_cpp")

mem = Memory()

# Load program segments into the memory
for ph in elf.program_header.entries:
    data = ph.data_to_load_to_memory
    print("writing a segment: %d bytes at pos 0x%x" % (len(data), ph.p_vaddr))
    mem.write(ph.p_vaddr, data)

cpu = Cpu(mem, elf.elf_header.e_entry, 0x123456789ABCDEF)

linux = Linux(cpu, mem)

cpu.linux = linux

# set gs and fs to non-zero values
# TODO: initialize to meaningful values
cpu.gs = 0xeeeeeeeeeeee
cpu.fs = 0xf0f0f0f0f0f0

try:
    while not cpu.stopped:
        print("=====")
        print("pos = 0x%x" % cpu.mem_stream.pos)
        cpu.exectute_next_instruction()
except Exception:
    for i in range(16):
        print("register #%d -> " % i, end='')
        cpu.register[i].debug()

    print(f"flags: {cpu.flags}")
    print("stack: 0x%x" % cpu.stack.pos)

    traceback.print_exc()
