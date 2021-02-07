import struct


class ElfHeader:
    def __init__(self, file):
        self.e_ident = {}

        e_ident_restrictions = [
            ['MAG0', [0x7F]],
            ['MAG1', [0x45]],
            ['MAG2', [0x4C]],
            ['MAG3', [0x46]],
            ['EI_CLASS', [1, 2]],
            ['EI_DATA', [1, 2]],
            ['EI_VERSION', [1]],
            ['EI_OSABI', [*range(0x12+1)]],
            ['EI_ABIVERSION', [*range(256)]],
            ['EI_PAD0', [0]],
            ['EI_PAD1', [0]],
            ['EI_PAD2', [0]],
            ['EI_PAD3', [0]],
            ['EI_PAD4', [0]],
            ['EI_PAD5', [0]],
            ['EI_PAD6', [0]],
        ]

        for field in e_ident_restrictions:
            name = field[0]
            value_range = field[1]
            value = list(file.read(1))[0]
            self.e_ident[name] = value

            if value not in value_range:
                raise Exception("bad %s in ELF header: 0x%02x" % [name, value])

        scheme = "<" if self.is_little_endian() else ">"
        if self.is_64_bit():
            scheme += 'HHLQQQLHHHHHH'
        else:
            scheme += 'HHLLLLLHHHHHH'

        buffer = file.read(struct.calcsize(scheme))

        self.e_type, self.e_machine, self.e_version, self.e_entry,
        self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
        self.e_phentsize, self.e_phnum, self.e_shentsize,
        self.e_shnum, self.e_shstrndx = struct.unpack(scheme, buffer)

    def is_little_endian(self):
        return self.e_ident['EI_DATA'] == 1

    def is_64_bit(self):
        return self.e_ident['EI_CLASS'] == 2


def read_data_to_load_to_memory(file, offset, size_in_file, size_in_memory):
    debug_info = "offset: %d" % offset
    debug_info += ", size in file: %d" % size_in_file
    debug_info += ", size in memory: %d" % size_in_memory
    print(debug_info)

    file.seek(offset)
    bytes = list(file.read(size_in_file))

    # fill with zeros if size_in_file < size_in_memory
    bytes += [0] * size_in_memory

    # take only the part that fits into memory
    return bytes[:size_in_memory]


class ElfProgramHeaderEntry:
    def __init__(self, file, elf_header):

        scheme = "<" if elf_header.is_little_endian() else ">"
        if elf_header.is_64_bit():
            scheme += "LLQQQQQQ"

            buffer = file.read(struct.calcsize(scheme))

            self.p_type, self.p_flags, self.p_offset, self.p_vaddr,\
                self.p_paddr, self.p_filesz, self.p_memsz, self.p_align =\
                struct.unpack(scheme, buffer)
        else:
            scheme += "LLLLLLLL"

            buffer = file.read(struct.calcsize(scheme))

            self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,\
                self.p_filesz, self.p_memsz, self.p_flags, self.p_align =\
                struct.unpack(scheme, buffer)

        self.data_to_load_to_memory = \
            read_data_to_load_to_memory(file, self.p_offset, self.p_filesz,
                                        self.p_memsz)


class ElfProgramHeader:
    def __init__(self, file, elf_header):
        self.entries = []
        for i in range(elf_header.e_phnum):
            file.seek(elf_header.e_phoff + elf_header.e_phentsize * i)
            self.entries.append(ElfProgramHeaderEntry(file, elf_header))


class ElfSectionHeaderEntry:
    def __init__(self, file, elf_header):

        scheme = "<" if elf_header.is_little_endian else ">"
        if elf_header.is_64_bit():
            scheme += "LLQQQQLLQQ"
        else:
            scheme += "LLLLLLLLLL"

        buffer = file.read(elf_header.e_shentsize)

        self.sh_name, self.sh_type, self.sh_flags, self.sh_addr,
        self.sh_offset, self.sh_size, self.sh_link, self.sh_info,
        self.sh_addralign, self.sh_entsize = struct.unpack(scheme, buffer)


class ElfSectionHeader:
    def __init__(self, file, elf_header):
        self.entries = []
        for i in range(elf_header.e_shnum):
            file.seek(elf_header.e_shoff + i * elf_header.e_shentsize)
            self.entries.append(ElfSectionHeaderEntry(file, elf_header))


class Elf:
    def __init__(self, filename):
        file = open(filename, "rb")

        self.elf_header = ElfHeader(file)
        self.program_header = ElfProgramHeader(file, self.elf_header)
        self.section_header = ElfSectionHeader(file, self.elf_header)
