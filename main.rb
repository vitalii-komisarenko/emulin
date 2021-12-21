require_relative "elf_parser"
require_relative "memory"
require_relative "cpu"
require_relative "linux"

class Environment
    attr_reader :pointers_addr, :values_addr

    def initialize(mem, vars, pointers_addr, values_addr)
        @pointers_addr = pointers_addr
        @values_addr = values_addr

        for var in vars
            ptr = Pointer.new(mem, @pointers_addr, 8)
            @values_addr = mem.write_null_terminated_string(@values_addr, var)
            ptr.write_int(@values_addr)
            @pointers_addr -= 8
        end

        @pointers_addr -= 8
    end
end

class AuxillaryVector
    attr_reader :pos

    AT_SYSINFO_EHDR = 33
    AT_HWCAP = 16
    AT_PAGESZ = 6
    AT_CLKTCK = 17
    AT_PHDR = 3
    AT_PHENT = 4
    AT_PHNUM = 5
    AT_BASE = 7
    AT_FLAGS = 8
    AT_ENTRY = 9
    AT_UID = 11
    AT_EUID = 12
    AT_GID = 13
    AT_EGID = 14
    AT_SECURE = 23
    AT_RANDOM = 25
    AT_HWCAP2 = 26
    AT_EXECFN = 31
    AT_PLATFORM = 15
    AT_NULL = 0

    def initialize(mem, pos)
        @pos = pos

        file_name = __dir__ + "/progs_to_test/bin/hello_cpp"
        file_name_addr = 0x7fffffffefc6
        platform = "x86_64"
        platform_addr = 0x7fffffffe279

        data = [
            [AT_SYSINFO_EHDR, 0x7ffff7ffd000],
            [AT_HWCAP, 0x178bfbff],
            [AT_PAGESZ, 4096],
            [AT_CLKTCK, 100],
            [AT_PHDR, 0x400040],
            [AT_PHENT, 56],
            [AT_PHNUM, 10],
            [AT_BASE, 0x0],
            [AT_FLAGS, 0x0],
            [AT_ENTRY, 0x404b00],
            [AT_UID, 1000],
            [AT_EUID, 1000],
            [AT_GID, 1000],
            [AT_EGID, 1000],
            [AT_SECURE, 0],
            [AT_RANDOM, 0x7fffffffe269],
            [AT_HWCAP2, 0x2],
            [AT_EXECFN, file_name_addr],
            [AT_PLATFORM, platform_addr],
            [AT_NULL, 0x0]
        ]

        for i in data.reverse
            ptr = Pointer.new(mem, @pos, 8)
            ptr.write_int(i[0])
            @pos -= 8
            ptr = Pointer.new(mem, @pos, 8)
            ptr.write_int(i[1])
            @pos -= 8
        end

        mem.write_null_terminated_string(file_name_addr, file_name)
        mem.write_null_terminated_string(platform_addr, platform)
    end
end

stack_bottom = 0x7fffffffef10
values_addr  = 0x7fffffffedd8


file = Dir.pwd + "/progs_to_test/bin/hello_cpp"

elf = Elf.new(file)

raise "64-bit ELF required" unless elf.elf_header.is_64_bit

mem = Memory.new

# Load program segments into the memory
elf.program_header.entries.each do |ph|
    puts "writing a segment: %d bytes at position 0x%x" % [ph.data_to_load_to_memory.length, ph.p_vaddr]
    mem.write(ph.p_vaddr, ph.data_to_load_to_memory)
end

auxv = AuxillaryVector.new(mem, stack_bottom)
env = Environment.new(mem, ['BASH_ENV=/dev/null'], auxv.pos, values_addr)

stack_bottom = env.pointers_addr

initial_stack_data = [
0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x59, 0xef, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8b, 0xef, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00,
0xab, 0xef, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0xb3, 0xef, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0xd0, 0xff, 0xf7, 0xff, 0x7f, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xff, 0xfb, 0x8b, 0x17, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x40, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x4b, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x39, 0xef, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xc6, 0xef, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x49, 0xef, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0xd4, 0x9f, 0x52, 0xeb, 0x4a, 0x44,
0x73, 0x1a, 0xfa, 0x99, 0x90, 0x37, 0x0d, 0xc1, 0x1c, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x76,
0x6b, 0x2f, 0x70, 0x72, 0x6f, 0x67, 0x73, 0x2f, 0x65, 0x6d, 0x75, 0x6c, 0x69, 0x6e, 0x2f, 0x70,
0x72, 0x6f, 0x67, 0x73, 0x5f, 0x74, 0x6f, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x2f, 0x62, 0x69, 0x6e,
0x2f, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x5f, 0x63, 0x70, 0x70, 0x00, 0x50, 0x57, 0x44, 0x3d, 0x2f,
0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x76, 0x6b, 0x2f, 0x70, 0x72, 0x6f, 0x67, 0x73, 0x2f, 0x65, 0x6d,
0x75, 0x6c, 0x69, 0x6e, 0x2f, 0x75, 0x74, 0x69, 0x6c, 0x73, 0x00, 0x53, 0x48, 0x4c, 0x56, 0x4c,
0x3d, 0x30, 0x00, 0x42, 0x41, 0x53, 0x48, 0x5f, 0x45, 0x4e, 0x56, 0x3d, 0x2f, 0x64, 0x65, 0x76,
0x2f, 0x6e, 0x75, 0x6c, 0x6c, 0x00, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x76, 0x6b, 0x2f, 0x70,
0x72, 0x6f, 0x67, 0x73, 0x2f, 0x65, 0x6d, 0x75, 0x6c, 0x69, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x67,
0x73, 0x5f, 0x74, 0x6f, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x68, 0x65,
0x6c, 0x6c, 0x6f, 0x5f, 0x63, 0x70, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]

mem.write(0x7fffffffedc0, initial_stack_data)

cpu = Cpu.new(mem, elf.elf_header.e_entry, stack_bottom)

linux = Linux.new(cpu, mem)

cpu.linux = linux
cpu.file  = file

while !cpu.stopped
    puts "====="
    puts cpu
    cpu.exectute_next_instruction
end
