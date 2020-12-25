require_relative "stream"
require_relative "pointer"
require_relative "const_buffer"

class InstructionPrefix
	@@prefixes_to_ignore = [
		0xF0, # LOCK prefix
		0x2E, # CS segment override - ignored in 64-bit mode
		0x36, # SS segment override - ignored in 64-bit mode
		0x3E, # DS segment override - ignored in 64-bit mode
		0x26, # ES segment override - ignored in 64-bit mode
		0x2E, # Branch not taken
		0x3E, # Branch taken 
	]

	@@prefixes_not_implemented = [
		0xF2, # REPNE/REPNZ prefix
		0xF3, # REP or REPE/REPZ prefix 
		0x64, # FS segment override
		0x65, # GS segment override
	]

	attr_reader :operand_size_overridden, :address_size_overridden
	
	def initialize(stream)
		@operand_size_overridden = false
		@address_size_overridden = false
	
		loop do
			prefix = stream.read

			case prefix
			when *@@prefixes_to_ignore
				"ignore"
			when *@@prefixes_not_implemented
				raise "prefix %x not implemented" % prefix
			when 0x66 # Operand-size override prefix
				operand_size_overridden = true
			when 0x67 # Address-size override prefix
				address_size_overridden = true
			else
				# all the prefixes have been read
				stream.back
				break
			end
		end
	end
end

class REX
	attr_reader :rex, :w, :r, :x, :b

	def initialize(stream)
		byte = stream.read
		if (byte >= 0x40) and (byte <= 0x4F)
			@rex = byte
		else
			stream.back
			@rex = 0
		end
		@w = (@rex & 0x8) >> 3
		@r = (@rex & 0x4) >> 2
		@x = (@rex & 0x2) >> 1
		@b = (@rex & 0x1)
	end
end

class Instruction
	attr_reader :function, :arguments
	def initialize(stream, cpu, linux)
		@stream = stream
		@cpu = cpu
		@linux = linux

		@prefix = InstructionPrefix.new(stream)
		@rex = REX.new(stream)
		@opcode = read_opcode(stream)
		@modrm = nil
		
		@func = nil # operation to be done (e.g. 'add', 'mov' etc.)
		@size = nil # operand size (in bytes)
		@args = []  # operation arguments. If operation result is to be stored
		            # the destination is encoded in the first argument
		
		case @opcode
		when 0x50..0x57
			@func = "push"
			@size = multi_byte
			decode_register_from_opcode
		when 0x58..0x5F
			@func = "pop"
			@size = multi_byte
			decode_register_from_opcode
		when 0x70..0x7F
			@func = ['jo', 'jno', 'jb', 'jnb', 'jz', 'jnz', 'jbe', 'jnbe',
			         'js', 'jns', 'jp', 'jnp', 'jl', 'jnl', 'jle', 'jnle'][@opcode - 0x70]
			rel8 = @stream.read_pointer(1).read_signed
			@args.push(@stream.pos + rel8)
		when 0x80, 0x81, 0x83
			@size = @opcode == 0x80 ? 1 : multi_byte
			parse_modrm
			@func = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][@modrm.opcode_ext]
			@args = [ @modrm.register_or_memory ]

			if @opcode == 0x81
				decode_immediate_16or32
			else
				decode_immediate 1
			end
		when 0xb8..0xbf
			@func = "mov"
			@size = multi_byte
			decode_register_from_opcode
			decode_immediate
		when 0xC0, 0xC1, 0xD0..0xD3
			@size = @opcode % 2 ? 1 : multi_byte
			parse_modrm
			@func = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"][@modrm.opcode_ext]
			@args = [ @modrm.register_or_memory ]
			if [0xC0, 0xC1].include? @opcode
				decode_immediate 1
			elsif [0xD0, 0xD1].key? @opcode
				@args.push ConstBuffer.new(1).ptr
			else
				@args.push ConstBuffer.new(@cpu.flags.c ? 1 : 0).ptr
			end
		when 0xC6
			# TODO: verify opcode extension
			@func = "mov"
			@size = 1
			parse_modrm
			@args.push @modrm.register_or_memory
			decode_immediate
		when 0xC7
			# TODO: verify opcode extension
			@func = "mov"
			@size = multi_byte
			parse_modrm
			@args.push @modrm.register_or_memory
			decode_immediate_16or32
		when 0xE8
			if @prefix.operand_size_overridden
				raise "Use of operand-size prefix in 64-bit mode may result in implementation-dependent behaviour"
			end
			@func = "call"
			rel32 = @stream.read_pointer(4).read_signed
			@args.push ConstBuffer.new(2 ** 64 + @cpu.mem_stream.pos + rel32).ptr
		when 0x0F05
			@func = "syscall"
		else
			if @@reg_regmem_opcodes.key? @opcode
				arr = @@reg_regmem_opcodes[@opcode]
				@func = arr[0]
				is8bit = arr[1] == 1
				direction_bit = arr[2] == 1

				@size = is8bit ? 1 : multi_byte
				
				parse_modrm
				
				@args.push @modrm.register
				@args.push @modrm.register_or_memory
				if direction_bit
					@args[0], @args[1] = @args[1], @args[0]
				end
			elsif @@no_args_opcodes.key? @opcode
				@func = @@reg_regmem_opcodes[@opcode]
			else
				raise "not implemented: opcode 0x%x" % @opcode
			end
		end
	end
	
	def decode_register_from_opcode
		reg = (@opcode & 8) + 8 * @rex.b
		@args.push Pointer.new(@cpu.register[reg], 0, @size)
	end
	
	def decode_immediate(size = @size)
		@args.push @stream.read_pointer(size)
	end

	def decode_immediate_16or32
		size = @size == 8 ? 4 : @size
		decode_immediate(size)
	end

	def parse_modrm
		address_size = @prefix.address_size_overridden ? 4 : 8
		@modrm = ModRM_Parser.new(@stream, @rex, @cpu, @size, address_size)
	end

	def read_opcode(stream)
		byte1 = stream.read
		if byte1 == 0x0F
			byte2 = stream.read
			case byte2
			when 0x38
				byte3 = stream.read
				return 0x0F3800 + byte3
			when 0x3A
				byte3 = stream.read
				return 0x0F3A00 + byte3
			else
				return 0x0F00 + byte2
			end
		else
			return byte1
		end
	end
	
	def execute
		puts "opcode: %x" % @opcode
		puts @func
		for arg in @args
			puts "arg = %s pos=%x size=%d ==> %s" % [arg.mem.name, arg.pos, arg.size, arg.debug_value]
		end
		case @func
		when "mov"
			@args[0].write @args[1].read
		when "xchg"
			tmp = @args[1].read
			@args[1].write @args[0].read
			@args[0].write tmp
		when "pop"
			@args[0].write @cpu.stack.pop @size
		when "push"
			@cpu.stack.push @args[0].read
		when "call"
			@cpu.stack.push [@cpu.rip].pack("Q<").unpack("C*")
			@cpu.rip = @args[0].read_int
		when "syscall"
			syscall_number = @cpu.register[0].read(0, 8).pack("C*").unpack("Q<")[0]
			@linux.handle_syscall(syscall_number, [
				@cpu.register[7].read(0, 8).pack("C*").unpack("Q<")[0],
				@cpu.register[6].read(0, 8).pack("C*").unpack("Q<")[0],
				@cpu.register[2].read(0, 8).pack("C*").unpack("Q<")[0],
				@cpu.register[10].read(0, 8).pack("C*").unpack("Q<")[0],
				@cpu.register[8].read(0, 8).pack("C*").unpack("Q<")[0],
				@cpu.register[9].read(0, 8).pack("C*").unpack("Q<")[0],
			])
		when 'xor'
			value = @args[0].read_int ^ @args[1].read_int
			@args[0].write_int value
			update_flags("...sz.p.", value, @args[0].size)
			@cpu.flags.o = false
			@cpu.flags.c = false
		when 'or'
			value = @args[0].read_int | @args[1].read_int
			@args[0].write_int value
			update_flags("...sz.p.", value, @args[0].size)
			@cpu.flags.o = false
			@cpu.flags.c = false
		when 'and'
			value = @args[0].read_int & @args[1].read_int
			@args[0].write_int value
			update_flags("...sz.p.", value, @args[0].size)
			@cpu.flags.o = false
			@cpu.flags.c = false
		when 'add', 'adc'
			highest_bit1 = Utils.highest_bit_set(@args[0].read_int, @args[0].size)
			highest_bit2 = Utils.highest_bit_set(@args[1].read_int, @args[1].size)
			
			cf = ((@func == 'adc') && @cpu.flags.c) ? 1 : 0
			value = @args[0].read_int + @args[1].read_signed + cf + (2 ** (8 * @size))
			@args[0].write_int value

			@cpu.flags.c = value >= 2 ** (8 * @args[0].size)

			highest_res  = Utils.highest_bit_set(@args[1].read_int, @args[1].size)
			
			@cpu.flags.o = (highest_res && !highest_bit1 && !highest_bit2) ||
			               (!highest_res && highest_bit1 && highest_bit2)

			update_flags("...sz.p.", value, @args[0].size)
			# TODO: @cpu.flags.a
		when "rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"
			times = @args[1].read_int % (2 ** @size)
			times.times do
				case @func
				when "rol"
					highest_bit = @args[0].highest_bit
					@args[0].write_int(@args[0].read_int * 2 + highest_bit)
					@cpu.flags.c = highest_bit == 1
					@cpu.flags.o = @cpu.flags.c ^ (@args[0].highest_bit == 1)
				when "ror"
					orig_highest_bit = @args[0].highest_bit
					value = @args[0].read_int
					@cpu.flags.c = value & 1 == 1
					@args[0].write_int(value / 2)
					@cpu.flags.o = orig_highest_bit == 1
				else
					raise "function not implemented: " + @func
				end
			end
		when 'jo'
			jump @arg[0] if @cpu.flags.o
		when 'jno'
			jump @arg[0] if !@cpu.flags.o
		when 'jb'
			jump @arg[0] if @cpu.flags.c
		when 'jnb'
			jump @arg[0] if !@cpu.flags.c
		when 'jz'
			jump @arg[0] if @cpu.flags.z
		when 'jnz'
			jump @arg[0] if !@cpu.flags.z
		when 'jbe'
			jump @arg[0] if @cpu.flags.c and @cpu.flags.z
		when 'jnbe'
			jump @arg[0] if !@cpu.flags.c and !@cpu.flags.z
		when 'js'
			jump @arg[0] if @cpu.flags.s
		when 'jns'
			jump @arg[0] if !@cpu.flags.s
		when 'jp'
			jump @arg[0] if @cpu.flags.p
		when 'jnp'
			jump @arg[0] if !@cpu.flags.p
		when 'jl'
			jump @arg[0] if @cpu.flags.s != @cpu.flags.o
		when 'jnl'
			jump @arg[0] if @cpu.flags.s == @cpu.flags.o
		when 'jle'
			jump @arg[0] if @cpu.flags.z and (@cpu.flags.s != @cpu.flags.o)
		when 'jnle'
			jump @arg[0] if !@cpu.flags.z and (@cpu.flags.s == @cpu.flags.o)
		when 'cmc' # Complement Carry Flag
			@cpu.flags.c = !@cpu.flags.c
		when 'clc', # Clear Carry Flag
			@cpu.flags.c = false
		when 'stc', # Set Carry Flag
			@cpu.flags.c = true
		when 'cld', # Clear Direction Flag
			@cpu.flags.d = false
		when 'std', # Set Direction Flag
			@cpu.flags.d = true
		else
			raise "function not implemented: " + @func
		end
	end

	def update_flags(pattern, value, size)
		for flag in pattern.split(//)
			case flag
			when 's' # sign flag
				@cpu.flags.s = Utils.highest_bit_set(value, size)
			when 'z' # zero flag
				@cpu.flags.z = value == 0
			when 'p' # parity flag -- check if the lowest bit is zero
				@cpu.flags.p = value & 1 == 0
			when '.', '-'
			else
				raise "unsupported flag: " + flag
			end
		end
		
	end

	# calculate operand size if operand size is not 1 ("multi-byte")
	def multi_byte
		if @rex.w == 1
			return 8
		elsif @prefix.operand_size_overridden
			return 2
		else
			return 4
		end
	end
	
	def jump(pos)
		@stream.pos = pos
	end
	
	@@reg_regmem_opcodes = {
		# format: opcode: [operation, is8bit, direction_bit]
		0x00 => ['add', 1, 1],
		0x01 => ['add', 0, 1],
		0x02 => ['add', 1, 0],
		0x03 => ['add', 0, 0],
		0x08 => ['or', 1, 1],
		0x09 => ['or', 0, 1],
		0x0A => ['or', 1, 0],
		0x0B => ['or', 0, 0],
		0x10 => ['adc', 1, 1],
		0x11 => ['adc', 0, 1],
		0x12 => ['adc', 1, 0],
		0x13 => ['adc', 0, 0],
		0x18 => ['sbb', 1, 1],
		0x19 => ['sbb', 0, 1],
		0x1A => ['sbb', 1, 0],
		0x1B => ['sbb', 0, 0],
		0x20 => ['and', 1, 1],
		0x21 => ['and', 0, 1],
		0x22 => ['and', 1, 0],
		0x23 => ['and', 0, 0],
		0x28 => ['sub', 1, 1],
		0x29 => ['sub', 0, 1],
		0x2A => ['sub', 1, 0],
		0x2B => ['sub', 0, 0],
		0x30 => ['xor', 1, 1],
		0x31 => ['xor', 0, 1],
		0x32 => ['xor', 1, 0],
		0x33 => ['xor', 0, 0],
		0x38 => ['cmp', 1, 1],
		0x39 => ['cmp', 0, 1],
		0x3A => ['cmp', 1, 0],
		0x3B => ['cmp', 0, 0],
		0x86 => ['xchg', 1, nil],
		0x87 => ['xchg', 0, nil],
		0x88 => ['mov', 1, 1],
		0x89 => ['mov', 0, 1],
		0x8A => ['mov', 1, 0],
		0x8B => ['mov', 0, 0],
	}
	
	@@no_args_opcodes = {
        0xF5 => 'cmc', # Complement Carry Flag
        0xF8 => 'clc', # Clear Carry Flag
        0xF9 => 'stc', # Set Carry Flag
        0xFA => 'cli', # Clear Interrupt Flag
        0xFB => 'sti', # Set Interrupt Flag
        0xFC => 'cld', # Clear Direction Flag
        0xFD => 'std', # Set Direction Flag
	}
end

class ModRM_Parser
	def initialize(stream, rex, cpu, operand_size, address_size)
		@rex = rex
		@stream = stream
		@modrm = stream.read
		@cpu = cpu
		@operand_size = operand_size
		@address_size = address_size
	end
	
	def mode
		return (@modrm >> 6) & 0x3
	end
	
	def opcode_ext
		return (@modrm & 0x38) >> 3
	end
	
	def register
		index = ((@modrm & 0x38) >> 3) + 8 * @rex.r
		return Pointer.new(@cpu.register[index], 0, @operand_size)
	end
	
	def register_or_memory
		regmem = (@modrm & 0x07) + 8 * @rex.b
		if mode == 0x03
			return Pointer.new(@cpu.register[regmem], 0, @operand_size)		
		else
			if [0x4, 0xC].include? regmem
				return sib
			elsif [0x5, 0xD].include? regmem
				raise "RIP/EIP addressing not implemented"
			else
				addr = @cpu.register[regmem].read_int(0, @address_size)
				case mode
				when 0x1
					addr += disp8
				when 0x2
					addr += disp32
				end
				return memory_at (addr % (2 ** (8 * @address_size)))
			end
		end
	end
	
	def memory_at(pos)
		p "memory_at %x" % pos
		return Pointer.new(@stream.mem, pos % @address_size, @operand_size) 
	end
	
	def disp32
		b1 = @stream.read
		b2 = @stream.read
		b3 = @stream.read
		b4 = @stream.read
		
		return (256 ** 3) * (b4 - 0x80) + (256 ** 2) * b3 + 256 * b2 + b1
	end
	
	def disp8
		return @stream.read - 0x80
	end
	
	def sib
		sib = @stream.read
		@scale = 2 ** (sib >> 6)
		@index_reg = ((sib >> 3) & 0x07) + 8 * @rex.x
		@base_reg = (sib & 0x07) + 8 * @rex.b

		if @index_reg == 4
			@index = 0
		else
			@index = @cpu.register[@index_reg].read_int(0, @address_size)
		end

		@base = @cpu.register[@base_reg].read_int(0, @address_size)

		case mode
		when 0x0
			if [0x5, 0xD].include? @base_reg
				return memory_at(@index * @scale + disp32)
			else
				return memory_at(@base + @index * @scale)
			end
		when 0x1
			return memory_at(@base + @index * @scale + disp8)
		when 0x2			
			return memory_at(@base + @index * @scale + disp32)			
		end
	end
end