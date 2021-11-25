class ElfHeader
    def initialize(file)
        @e_ident = {}
        
        e_ident_restrictions = [
            ['MAG0', [0x7F]],
            ['MAG1', [0x45]],
            ['MAG2', [0x4C]],
            ['MAG3', [0x46]],
            ['EI_CLASS', [1, 2]],
            ['EI_DATA', [1, 2]],
            ['EI_VERSION', [1]],
            ['EI_OSABI', (0..0x12).to_a],
            ['EI_ABIVERSION', (0..0xFF).to_a],
            ['EI_PAD0', [0]],
            ['EI_PAD1', [0]],
            ['EI_PAD2', [0]],
            ['EI_PAD3', [0]],
            ['EI_PAD4', [0]],
            ['EI_PAD5', [0]],
            ['EI_PAD6', [0]],
        ]
        
        e_ident_restrictions.each do |field|
            name = field[0]
            value_range = field[1]
            value = file.read(1).unpack('C')[0]
            @e_ident[name] = value
            raise "bad %s in ELF header: 0x%02x" % [name, value] unless value_range.include? value
        end
        
        scheme = is_little_endian ? (is_64_bit ? 'S<S<L<Q<Q<Q<L<S<S<S<S<S<S<' : 'S<S<L<L<L<L<L<S<S<S<S<S<S<')
                                  : (is_64_bit ? 'S>S>L>Q>Q>Q>L>S>S>S>S>S>S>' : 'S>S>L>L>L>L>L>S>S>S>S>S>S>')
        
        remaining_header_size = (is_64_bit ? 0x40 : 0x34) - 0x10
        
        @e_type, @e_machine, @e_version, @e_entry, @e_phoff,
        @e_shoff, @e_flags, @e_ehsize, @e_phentsize, @e_phnum,
        @e_shentsize, @e_shnum, @e_shstrndx = file.read(remaining_header_size).unpack(scheme)
    end

    attr_reader :e_type, :e_machine, :e_version, :e_entry, :e_phoff,
                :e_shoff, :e_flags, :e_ehsize, :e_phentsize, :e_phnum,
                :e_shentsize, :e_shnum, :e_shstrndx
    
    def is_little_endian
        return @e_ident['EI_DATA'] == 1
    end
    
    def is_64_bit
        return @e_ident['EI_CLASS'] == 2
    end
end

def read_data_to_load_to_memory(file, offset, size_in_file, size_in_memory)
    puts "offset: %d, size in file: %d, size in memory: %d" % [offset, size_in_file, size_in_memory]
    file.seek(offset)
    bytes = file.read(size_in_file).unpack("C*")
    # fill with zeros if size_in_file < size_in_memory
    bytes += Array.new(size_in_memory, 0)
    # take only the part that fits into memory
    return bytes.slice(0, size_in_memory)
end

class ElfProgramHeaderEntry
    def initialize(file, elf_header)
        if elf_header.is_64_bit
            scheme = elf_header.is_little_endian ? "L<L<Q<Q<Q<Q<Q<Q<" : "L>L>Q>Q>Q>Q>Q>Q>";
            @p_type, @p_flags, @p_offset, @p_vaddr,
            @p_paddr, @p_filesz, @p_memsz, @p_align = file.read(elf_header.e_phentsize).unpack(scheme)
        else
            scheme = elf_header.is_little_endian ? "L<L<L<L<L<L<L<L<" : "L>L>L>L>L>L>L>L>";
            @p_type, @p_offset, @p_vaddr, @p_paddr,
            @p_filesz, @p_memsz, @p_flags, @p_align = file.read(elf_header.e_phentsize).unpack(scheme)
        end
        
        @data_to_load_to_memory = read_data_to_load_to_memory(file, @p_offset, @p_filesz, @p_memsz)
    end
    
    attr_reader :p_type, :p_flags, :p_offset, :p_vaddr,
                :p_paddr, :p_filesz, :p_memsz, :p_align,
                :data_to_load_to_memory
end

class ElfProgramHeader
    def initialize(file, elf_header)
        @entries = []
        for i in 0..elf_header.e_phnum - 1 do
            file.seek(elf_header.e_phoff + elf_header.e_phentsize * i)
            @entries.append(ElfProgramHeaderEntry.new(file, elf_header))
        end
    end
    
    attr_reader :entries
end

class ElfSectionHeaderEntry
    def initialize(file, elf_header)
        if elf_header.is_64_bit
            scheme = elf_header.is_little_endian ? "L<L<Q<Q<Q<Q<L<L<Q<Q<" : "L>L>Q>Q>Q>Q>L>L>Q>Q>"
        else
            scheme = elf_header.is_little_endian ? "L<L<L<L<L<L<L<L<L<L<" : "L>L>L>L>L>L>L>L>L>L>"
        end
        @sh_name, @sh_type, @sh_flags, @sh_addr, @sh_offset, @sh_size, @sh_link,
        @sh_info, @sh_addralign, @sh_entsize = file.read(elf_header.e_shentsize).unpack(scheme)
    end
    
    attr_reader :sh_name, :sh_type, :sh_flags, :sh_addr, :sh_offset, :sh_size, :sh_link,
                :sh_info, :sh_addralign, :sh_entsize
end

class ElfSectionHeader
    def initialize(file, elf_header)
        @entries = []
        for i in 0..elf_header.e_shnum - 1 do
            file.seek(elf_header.e_shoff + i * elf_header.e_shentsize)
            @entries.append(ElfSectionHeaderEntry.new(file, elf_header))
        end
    end
    
    attr_reader :entries
end

class Elf
    def initialize(filename)
        File.open(filename) do |file|
            @elf_header = ElfHeader.new(file)
            @program_header = ElfProgramHeader.new(file, @elf_header)
            @section_header = ElfSectionHeader.new(file, @elf_header)
        end
    end
    
    attr_reader :elf_header, :program_header, :section_header
end