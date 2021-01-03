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

	attr_reader :operand_size_overridden, :address_size_overridden, :segment,
	            :repe, :repne, :rex_w, :reg_extension, :rex_x, :rex_b
	
	def initialize(stream)
		@operand_size_overridden = false
		@address_size_overridden = false
		@repe = false
		@repne = false
		@segment = "none"

		@rex_w = 0
		@reg_extension = 0
		@rex_x = 0
		@rex_b = 0
	
		loop do
			prefix = stream.read

			case prefix
			when *@@prefixes_to_ignore
				"ignore"
			when 0x40..0x4F # REX prefix
				@rex_w = prefix[3]
				@reg_extension = 8 * prefix[2]
				@rex_x = prefix[1]
				@rex_b = prefix[0]
			when 0x64 # FS segment override
				@segment = "FS"
			when 0x65 # GS segment override
				@segment = "GS"
			when 0x66 # Operand-size override prefix
				@operand_size_overridden = true
			when 0x67 # Address-size override prefix
				@address_size_overridden = true
			when 0xF2 # REPNE/REPNZ prefix
				@repne = true
			when 0xF3 # REP or REPE/REPZ prefix
				@repe = true
			else
				# all the prefixes have been read
				stream.back
				break
			end
		end
	end

	def simd_prefix
		arr = []
		arr.push 0x66 if @operand_size_overridden
		arr.push 0xF2 if @repne
		arr.push 0xF3 if @repe
		if arr.length > 1
			raise "only one SIMD prefix expected, but several provided: " + arr.map{|x| "%02X" % x}.join(", ")
		end
		return arr[0]
	end
end

class Instruction
	attr_reader :function, :arguments
	def initialize(stream, cpu, linux)
		@stream = stream
		@cpu = cpu
		@linux = linux

		@prefix = InstructionPrefix.new(stream)
		@opcode = read_opcode(stream)
		@modrm = nil
		
		@func = nil # operation to be done (e.g. 'add', 'mov' etc.)
		@size = nil # operand size (in bytes)
		@args = []  # operation arguments. If operation result is to be stored
		            # the destination is encoded in the first argument
		@cond = nil # condition to check for conditional operations (e.g. 'jne', 'cmovo')
		
		@xmm_item_size = nil
		
		@address_size = @prefix.address_size_overridden ? 4 : 8
		
		case @opcode
		when 0x00..0x3F
			raise "bad opcode: %02x" % @opcode if [6,7].include?(@opcode % 8)
			funcs = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
			params = [["size=1",     "r/m", "r"],
			          ["size=2/4/8", "r/m", "r"],
			          ["size=1",     "r",   "r/m"],
			          ["size=2/4/8", "r",   "r/m"],
			          ["size=1",     "acc", "imm1"],
			          ["size=2/4/8", "acc", "imm2/4"]]
			decode_arguments([funcs[modrm.opcode_ext]] + params[@opcode % 8])
		when 0x50..0x57
			@func = "push"
			@size = multi_byte
			decode_register_from_opcode
		when 0x58..0x5F
			@func = "pop"
			@size = multi_byte
			decode_register_from_opcode
		when 0x63
			@func = "movsxd"
			@size = multi_byte
			@args.push modrm.register
			modrm.operand_size = [4, modrm.operand_size].min
			@args.push modrm.register_or_memory
		when 0x68, 0x6A
			@func = "push"
			@size = @opcode == 0x68 ? multi_byte : 1
			decode_immediate_16or32
		when 0x0FBE..0x0FBF
			@func = "movsx"
			@size = multi_byte
			@args.push modrm.register
			modrm.operand_size = @opcode == 0x0FBE ? 1 : 2
			@args.push modrm.register_or_memory
		when 0x0FB6..0x0FB7
			@func = "movzx"
			@size = multi_byte
			@args.push modrm.register
			modrm.operand_size = @opcode == 0x0FB6 ? 1 : 2
			@args.push modrm.register_or_memory
		when 0x70..0x7F
			@func = "jmp"
			@cond = @opcode % 16
			decode_relative_address 1
		when 0x0F80..0x0F8F
			@func = "jmp"
			@cond = @opcode % 16
			# TODO: are 16-bit offset specified?
			decode_relative_address 4
		when 0x80, 0x81, 0x83
			@size = @opcode == 0x80 ? 1 : multi_byte
			@func = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][modrm.opcode_ext]
			@args = [ modrm.register_or_memory ]

			if @opcode == 0x81
				decode_immediate_16or32
			else
				decode_immediate 1
			end
		when 0x90
			@func = @prefix.repe ? "pause" : "nop"
		when 0x91..0x97
			@func = "xchg"
			@size = multi_byte
			encode_accumulator
			decode_register_from_opcode
		when 0xb0..0xb7
			@func = "mov"
			@size = 1
			decode_register_from_opcode
			decode_immediate
		when 0xb8..0xbf
			@func = "mov"
			@size = multi_byte
			decode_register_from_opcode
			decode_immediate
		when 0xC3
			@func = "retn"
			encode_value 0
		when 0xC6
			@func = "mov"
			@size = 1
			unspecified_opcode_extension unless modrm.opcode_ext == 0
			@args.push modrm.register_or_memory
			decode_immediate
		when 0xC7
			@func = "mov"
			@size = multi_byte
			unspecified_opcode_extension unless modrm.opcode_ext == 0
			@args.push modrm.register_or_memory
			decode_immediate_16or32
		when 0xE0..0xE2
			@func = ["loopnz", "loopz", "loop"][@opcode - 0xE0]
			encode_counter
			decode_relative_address 1
		when 0xE8
			if @prefix.operand_size_overridden
				raise "Use of operand-size prefix in 64-bit mode may result in implementation-dependent behaviour"
			end
			@func = "call"
			decode_relative_address 4
		when 0xE9
			if @prefix.operand_size_overridden
				raise "Use of operand-size prefix in 64-bit mode may result in implementation-dependent behaviour"
			end
			@func = "jmp"
			decode_relative_address 4
		when 0xEB
			@func = "jmp"
			decode_relative_address 1
		when 0xFE
			@size = 1
			unspecified_opcode_extension unless [0, 1].include? modrm.opcode_ext
			@func = modrm.opcode_ext == 0 ? "inc" : "dec"
			@args.push modrm.register_or_memory
			encode_value 1
		when 0xF6
			case modrm.opcode_ext
			when 0, 1
				@func = "test"
				@size = 1
				modrm.operand_size = 1
				@args.push modrm.register_or_memory
				decode_immediate_16or32
			else
				raise "opcode extension not implemented for opcode 0xF6: %d" % modrm.opcode_ext
			end
		when 0xF7
			@size = multi_byte
			case modrm.opcode_ext
			when 0, 1
				@func = "test"
				@args.push modrm.register_or_memory
				decode_immediate_16or32
			when 3
				@func = "neg"
				encode_value 0
				@args.push modrm.register_or_memory
			when 6
				@func = "div"
				@args.push modrm.register_or_memory
			else
				raise "opcode extension not implemented for opcode 0xF7: %d" % modrm.opcode_ext
			end
		when 0xFF
			case modrm.opcode_ext
			when 0, 1
				@func = modrm.opcode_ext == 0 ? "inc" : "dec"
				@size = multi_byte
				modrm.operand_size = multi_byte
				@args.push modrm.register_or_memory
				encode_value 1
			when 2, 4
				@func = @opcode == 4 ? "jmp" : "call"
				# TODO: unspecified behaviour for 16 and 32-bit operands
				@size = multi_byte
				modrm.operand_size = multi_byte
				ptr = modrm.register_or_memory
				encode_value ptr.read_int
			else
				raise "opcode extension not implemented for opcode 0xFF: %d" % modrm.opcode_ext
			end
		when 0x0F10..0x0F11
			if @prefix.operand_size_overridden || @prefix.repe || @prefix.repne
				raise "not implemented"
			end
			@func = "mov"
			@size = 16
			@args.push modrm.mm_or_xmm_register
			@args.push modrm.mm_or_xmm_register_or_memory
			@args = [@args[1], @args[0]] if @opcode == 0x0F11
		when 0x0F19..0x0F1F
			@size = multi_byte == 8 ? 4 : multi_byte
			@func = (@opcode == 0x0F1F) && (modrm.opcode_ext == 0) ? "nop" : "hint_nop"
			@args.push modrm.register_or_memory
		when 0x0F28
			@func = "movap"
			@size = 16
			@args.push modrm.mm_or_xmm_register
			@args.push modrm.mm_or_xmm_register_or_memory
		when 0x0F29
			@func = "movap"
			@size = 16
			@args.push modrm.mm_or_xmm_register_or_memory
			@args.push modrm.mm_or_xmm_register
		when 0x0F40..0x0F4F
			@func = "mov"
			@cond = @opcode % 16
			@size = multi_byte
			@args.push modrm.register
			@args.push modrm.register_or_memory
		when 0x0F6C, 0x0F6D
			# TODO: add support of VEX/EVEX
			@func = @opcode == 0x0F6C ? "punpckl" : "punpckh"
			raise "missing operand-size override prefix" unless @prefix.operand_size_overridden
			@size = 16
			@xmm_item_size = 8
			@args.push modrm.mm_or_xmm_register
			@args.push modrm.mm_or_xmm_register_or_memory
		when 0x0F6E
			@func = "movq"
			@size = mm_or_xmm_operand_size
			@args.push modrm.mm_or_xmm_register
			@size = @prefix.rex_w ? 8 : 4
			modrm.operand_size = @size
			@args.push modrm.register_or_memory
		when 0x0F6F
			# TODO: add support of VEX/EVEX
			@func = "mov"
			@size = mm_or_xmm_operand_size
			if @prefix.repe
				@size = 16
			end
			@xmm_item_size = 1
			@args.push modrm.mm_or_xmm_register
			@args.push modrm.mm_or_xmm_register_or_memory
		when 0x0F70
			# TODO: add support of VEX/EVEX
			# Note that VEX/EVEX versions clear some high bits
			case @prefix.simd_prefix
			when nil
				@func = "pshuf"
				@size = 8
				@xmm_item_size = 2
			when 0xF2 # Low bits
				@func = "pshufl"
				@size = 16
				@xmm_item_size = 2
			when 0xF3 # High bits
				@func = "pshufh"
				@size = 16
				@xmm_item_size = 2
			when 0x66
				@func = "pshuf"
				@size = 16
				@xmm_item_size = 4
			end
			@args.push modrm.mm_or_xmm_register
			@args.push modrm.mm_or_xmm_register_or_memory
			decode_immediate 1
		when 0x0F72
			@size = mm_or_xmm_operand_size
			case modrm.opcode_ext
			when 2,4
				raise "opcode extension not implemented"
			when 6
				@func = "psll"
				@xmm_item_size = 4
				@args.push modrm.mm_or_xmm_register_or_memory
				decode_immediate 1
			else
				unspecified_opcode_extension
			end
		when 0x0F73
			@size = mm_or_xmm_operand_size
			case modrm.opcode_ext
			when 2
				raise "not implemented"
			when 6
				@func = "psll"
				@xmm_item_size = 8
				@args.push modrm.mm_or_xmm_register_or_memory
				decode_immediate 1
			when 3, 7
				# TODO: verify that prefix 66 exists
				raise "not implemented"
			else
				unspecified_opcode_extension
			end
		when 0x0F7E
			# TODO: add support of VEX/EVEX
			@func = "movq"
			raise "not implemented" unless @prefix.repe
			@size = 16 # It is a workaround. ModR/M uses size to distinguish
			           # MMX and XMM registers
			@args.push modrm.mm_or_xmm_register
			@args[0].size = 8 # fix size
			@args.push modrm.mm_or_xmm_register_or_memory
			if modrm.mode == 0x3 # points to a register
				@args[1].size = 16 # fix size
			else
				@args[1].size = 8 # fix size
			end
		when 0x0F7F
			@func = "mov"
			@size = (@prefix.operand_size_overridden || @prefix.repe) ? 16 : 8
			@args.push modrm.mm_or_xmm_register_or_memory
			@args.push modrm.mm_or_xmm_register
		when 0x0FD6
			# TODO: add support of VEX/EVEX
			raise "not implemented" unless @prefix.operand_size_overridden
			@func = "movq"
			@size = 8
			@args.push modrm.xmm_register_or_memory
			@args.push modrm.xmm_register
			if modrm.mode == 0x3 # points to a register
				@args[1].size = 16 # to clear highest bits of the XMM register
			end
		when 0x0FD7
			@func = "pmovmsk"
			@size = 4
			@args.push modrm.register
			@size = mm_or_xmm_operand_size
			modrm.operand_size = @size
			@args.push modrm.mm_or_xmm_register_or_memory
		when 0x0FF0
			raise "F2 prefix expected" unless @prefix.repne
			@func = "mov"
			@size = 16
			@args.push modrm.xmm_register
			raise "register expected, but ModR/M mode is not 0b11" unless modrm.mode != 3
			@args.push modrm.xmm_register_or_memory
		when 0x0F90..0x0F9F
			@func = "set"
			@size = 1
			@args.push modrm.register_or_memory
			encode_value(condition_is_met(@opcode % 16) ? 1 : 0)
		else
			if @@reg_regmem_opcodes.key? @opcode
				arr = @@reg_regmem_opcodes[@opcode]
				@func = arr[0]
				is8bit = arr[1] == 1
				direction_bit = arr[2] == 1

				@size = is8bit ? 1 : multi_byte
				
				
				@args.push modrm.register
				@args.push modrm.register_or_memory
				if direction_bit
					@args[0], @args[1] = @args[1], @args[0]
				end
			elsif @@mm_xmm_reg_regmem_opcodes.key? @opcode
				# TODO: add support of VEX/EVEX
				arr = @@mm_xmm_reg_regmem_opcodes[@opcode]
				@func = arr[0]
				@xmm_item_size = arr[1]
				@size = mm_or_xmm_operand_size
				@args.push modrm.mm_or_xmm_register
				@args.push modrm.mm_or_xmm_register_or_memory
			elsif @@mm_xmm_reg_regmem_opcodes_signed.key? @opcode
				# TODO: add support of VEX/EVEX
				arr = @@mm_xmm_reg_regmem_opcodes_signed[@opcode]
				@func = arr[0]
				@xmm_item_size = arr[1]
				@size = mm_or_xmm_operand_size
				@args.push modrm.mm_or_xmm_register
				@args.push modrm.mm_or_xmm_register_or_memory
			elsif @@unified_opcode_table.key? @opcode
				arr = @@unified_opcode_table[@opcode]
				decode_arguments arr
			else
				raise "not implemented: opcode 0x%x" % @opcode
			end
		end
	end
	
	def decode_arguments(arr)
		@func = arr[0]
		case @func
		when "#ROTATE/SHIFT"
			@func = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"][modrm.opcode_ext]
		end

		tasks = arr[1..-1].nil? ? [] : arr[1..-1]
		for task in tasks
			case task
			when "size=1"
				@size = 1
			when "size=2/4/8"
				@size = multi_byte
			when "r"
				@args.push modrm.register
			when "r/m"
				@args.push modrm.register_or_memory
			when "acc"
				encode_accumulator
			when "imm"
				decode_immediate
			when "imm1"
				decode_immediate 1
			when "imm2/4"
				decode_immediate_16or32
			when "const=1"
				encode_value 1
			when "carry flag"
				encode_value(@cpu.flags.c ? 1 : 0)
			else
				raise "unknown task: %s"
			end

			# Currently ModR/M gets operand size on its first initalization
			# But in case of @func names like "#ROTATE/SHIFT" it is initalized
			# before size is set.
			# Workaround: update its size on each iteration
			@modrm.operand_size = @size unless @modrm.nil?
		end
	end

	def mm_or_xmm_operand_size
		# TODO: add support of VEX/EVEX
		return @prefix.operand_size_overridden ? 16 : 8
	end

	def encode_regiser(reg)
		@args.push Pointer.new(@cpu.register[reg], 0, @size)
	end

	def encode_accumulator
		encode_regiser(0)
	end

	def encode_counter
		encode_regiser(1)
	end

	def decode_register_from_opcode
		reg = (@opcode % 8) + 8 * @prefix.rex_b
		@args.push Pointer.new(@cpu.register[reg], 0, @size)
	end
	
	def decode_immediate(size = @size)
		@args.push @stream.read_signed_pointer(size)
	end

	def decode_immediate_16or32
		size = @size == 8 ? 4 : @size
		decode_immediate(size)
	end
	
	def encode_value(value, size = @size)
		size = size.nil? ? 8 : size
		@args.push ConstBuffer.new(value, size).ptr
	end
	
	def decode_relative_address(size)
		rel = @stream.read_pointer(size).read_signed
		encode_value(@cpu.rip + rel)
	end

	def modrm
		parse_modrm if @modrm.nil?
		@modrm
	end

	def parse_modrm
		address_size = @prefix.address_size_overridden ? 4 : 8
		@modrm = ModRM_Parser.new(@stream, @prefix, @cpu, @size, address_size, segment_offset)
	end

	def unspecified_opcode_extension
		raise "Unspecified opcode extension %d for opcode 0x%X" % [modrm.opcode_ext, @opcode]
	end

	def max_address
		return 256 ** @address_size
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
	
	def condition_is_met(cond = @cond)
		case cond
		when nil
			return true
		when 0
			return @cpu.flags.o
		when 1
			return !@cpu.flags.o
		when 2
			return @cpu.flags.c
		when 3
			return !@cpu.flags.c
		when 4
			return @cpu.flags.z
		when 5
			return !@cpu.flags.z
		when 6
			return @cpu.flags.c && @cpu.flags.z
		when 7
			return !@cpu.flags.c && !@cpu.flags.z
		when 8
			return @cpu.flags.s
		when 9
			return !@cpu.flags.s
		when 10
			return @cpu.flags.p
		when 11
			return !@cpu.flags.p
		when 12
			return @cpu.flags.s != @cpu.flags.o
		when 13
			return @cpu.flags.s == @cpu.flags.o
		when 14
			return @cpu.flags.z && (@cpu.flags.s != @cpu.flags.o)
		when 15
			return !@cpu.flags.z && (@cpu.flags.s == @cpu.flags.o)
		else
			raise "unexpected value of `cond`: %d" % cond
		end
	end
	
	def segment_offset
		return @cpu.fs * 16 if @prefix.segment == "FS"
		return @cpu.gs * 16 if @prefix.segment == "GS"
		return 0 if @prefix.segment == "none"
		raise "unexpected name of the segment: " + @prefix.segment
	end
	
	def execute
		puts "opcode: %x" % @opcode
		puts @func
		puts "condition: %s" % (@cond.nil? ? "none" : "%d" % @cond)
		for arg in @args
			puts "arg = %s pos=%x size=%d ==> %s" % [arg.mem.name, arg.pos, arg.size, arg.debug_value]
		end

		return unless condition_is_met

		case @func
		when "ins", "movs", "outs", "lods", "stos", "cmps", "scas"
			return execute_string_instruction
		when "lea"
			raise "LEA & register-direct addressing mode" if modrm.mode == 0x03
			@args[0].write_int @args[1].pos
		when "mov", "set", "movap"
			@args[0].write @args[1].read
		when "movq" # used in moving data from the lowest bits of XMM to XMM/memory
			@args[0].write_with_zero_extension @args[1].read
		when "movsxd", "movsx"
			@args[0].write_int @args[1].read_signed
		when "movzx"
			@args[0].write_int @args[1].read_int
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
		when "retn"
			@cpu.rip = @cpu.stack.pop(8).pack("C*").unpack("Q<")[0]
			@cpu.stack.pop(@args[0].read_int)
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
		when 'and', 'test'
			value = @args[0].read_int & @args[1].read_int
			@args[0].write_int(value) if @func == 'and'
			update_flags("...sz.p.", value, @args[0].size)
			@cpu.flags.o = false
			@cpu.flags.c = false
		when 'add', 'adc', 'inc'
			highest_bit1 = Utils.highest_bit_set(@args[0].read_int, @args[0].size)
			highest_bit2 = Utils.highest_bit_set(@args[1].read_int, @args[1].size)
			
			cf = ((@func == 'adc') && @cpu.flags.c) ? 1 : 0
			value = @args[0].read_int + @args[1].read_signed + cf
			@args[0].write_int value

			@cpu.flags.c = value >= 2 ** (8 * @args[0].size) unless @func == "inc"

			highest_res  = Utils.highest_bit_set(@args[0].read_int, @args[0].size)
			
			@cpu.flags.o = (highest_res && !highest_bit1 && !highest_bit2) ||
			               (!highest_res && highest_bit1 && highest_bit2)

			update_flags("...sz.p.", value, @args[0].size)
			# TODO: @cpu.flags.a
		when 'sub', 'sbb', 'cmp', 'dec', 'neg'
			highest_bit1 = Utils.highest_bit_set(@args[0].read_int, @args[0].size)
			highest_bit2 = Utils.highest_bit_set(@args[1].read_int, @args[1].size)

			cf = ((@func == 'sbb') && @cpu.flags.c) ? 1 : 0
			value = @args[0].read_int - @args[1].read_signed - cf
			@args[@func == 'neg' ? 1 : 0].write_int(value) unless @func == 'cmp'
			update_flags("...sz.p.", value, @args[0].size)

			@cpu.flags.c = value < 0 unless @func == "dec"

			highest_res = value[2 ** (8 * @size - 1)] == 1
			@cpu.flags.o = (!highest_bit1 && highest_bit2 && highest_res) ||
			               (highest_bit1 && !highest_bit2 && !highest_res)
			# TODO: @cpu.flags.a
		when 'xadd'
			@func = 'xchg'
			execute
			@func = 'add'
			execute
		when 'div'
			"div not implemented for size = 1" if @size == 1
			rax = Pointer.new(@cpu.register[0], 0, @size)
			rdx = Pointer.new(@cpu.register[2], 0, @size)
			dividend = (256 ** @size) * rdx.read_int + rax.read_int
			divisor = @args[0].read_int
			if divisor == 0
				raise "divide error exception: divisor = 0"
			end
			quotient = dividend / divisor
			remainder = dividend % divisor
			if quotient >= 256 ** @size
				raise "divide error exception: quotient too big: %d (dec) / %x (hex)" % [quotient, quotient]
			end
			rax.write_int quotient
			rdx.write_int remainder
		when 'imul'
			case @args.length
			when 1
				raise "not implemented"
			when 2
				@args = [@args[0]] + @args
			when 3
				# do nothing
			end
			value = @args[1].read_signed * @args[2].read_signed
			@args[0].write_int value
			@cpu.flags.c = (value < -(2**(8*@size-1)) || (value >= 2**(8*@size-1)))
			@cpu.flags.o = @cpu.flags.c
		when 'bsf'
			@cpu.flags.z = @args[1].read_int == 0
			@args[0].write_int @args[1].read_bit_array.index(1) unless @cpu.flags.z
		when 'bsr'
			@cpu.flags.z = @args[1].read_int == 0
			@args[0].write_int @args[1].read_bit_array.rindex(1) unless @cpu.flags.z
		when "rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"
			times = @args[1].read_int % (2 ** @size)
			bit_array = @args[0].read_bit_array
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
				when "rcl"
					bit_array.shift(@cpu.flags.c ? 1 : 0)
					@cpu.flags.c = (bit_array.pop) == 1
					@cpu.flags.o = @cpu.flags.c ^ (bit_array[-1] == 1)
					@args[0].write_bit_array bit_array					
				when "rcr"
					bit_array.push(@cpu.flags.c ? 1 : 0)
					@cpu.flags.c = (bit_array.unshift) == 1
					@cpu.flags.o = bit_array[-1] != bit_array[-2]
					@args[0].write_bit_array bit_array					
				when "shr", "sar"
					orig_highest_bit = bit_array[-1]
					bit_array.push(@func == "shr" ? 0 : bit_array[-1])
					@cpu.flags.c = bit_array.shift == 1
					@cpu.flags.o = (@func == "shr" ? orig_highest_bit == 1 : false) if times == 1
					@args[0].write_bit_array bit_array
				when "shl", "sal"
					bit_array.unshift 0
					@cpu.flags.c = bit_array.pop == 1
					@cpu.flags.o = @cpu.flags.c != (bit_array[-1] == 1) if times == 1
					@args[0].write_bit_array bit_array
				else
					raise "function not implemented: " + @func
				end
			end
		when 'jmp'
			jump @args[0]
		when 'loop', 'loopz', 'loopnz'
			rcx = @args[0]
			rcx.write_int(rcx.read_int - 1)
			return if rcx.read_int == 0
			jump @args[1] if @func == "loop"
			jump @args[1] if (@func == "loopz") && @cpu.flags.z
			jump @args[1] if (@func == "loopnz") && !@cpu.flags.z
		when 'sahf'
			ah = @cpu.register[0].read(1, 1)[0]
			@cpu.flags.c = ah[0]
			@cpu.flags.p = ah[2]
			@cpu.flags.a = ah[4]
			@cpu.flags.z = ah[6]
			@cpu.flags.s = ah[7]
		when 'lahf'
			ah = 0
			ah += @cpu.flags.c ? 1 : 0
			ah += 2
			ah += @cpu.flags.p ? 4 : 0
			ah += @cpu.flags.a ? 16 : 0
			ah += @cpu.flags.z ? 64 : 0
			ah += @cpu.flags.s ? 128 : 0
			@cpu.register[0].write(1, [ah])
		when 'cpuid'
			# Do nothing
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
		when 'nop', 'pause', "hint_nop"
			# do nothing
		when "pcmpeq"
			for_each_xmm_item(lambda{|dest, arg| dest == arg ? -1: 0})
		when "pxor"
			for_each_xmm_item(lambda{|dest, arg| dest ^ arg})
		when "pand"
			for_each_xmm_item(lambda{|dest, arg| dest & arg})
		when "pandn"
			for_each_xmm_item(lambda{|dest, arg| (~dest) & arg})
		when "por"
			for_each_xmm_item(lambda{|dest, arg| dest | arg})
		when "padd"
			for_each_xmm_item(lambda{|dest, arg| dest + arg})
		when "psub"
			for_each_xmm_item(lambda{|dest, arg| dest - arg})
		when "psubus"
			for_each_xmm_item(lambda{|dest, arg| [dest - arg, 0].max})
		when "paddus"
			for_each_xmm_item(lambda{|dest, arg| [dest + arg, 256 ** @xmm_item_size - 1].min})
		when "pminu"
			for_each_xmm_item(lambda{|dest, arg| [dest, arg].min})
		when "pmaxu"
			for_each_xmm_item(lambda{|dest, arg| [dest, arg].max})
		when "pavg"
			for_each_xmm_item(lambda{|dest, arg| (dest + arg + 1) >> 1})
		when "pcmpgt"
			for_each_xmm_item_signed(lambda{|dest, arg| dest > arg ? -1: 0})
		when "psll"
			for_each_xmm_item_and_constant(lambda{|dest, arg| dest << arg})
		when "psll"
			for_each_xmm_item_and_constant(lambda{|dest, arg| dest << arg})
		when "punpckl", "punpckh"
			arr = []
			for i in 0..(@size / @xmm_item_size)
				dest = Pointer.new(@args[0].mem, @args[0].pos + i * @xmm_item_size, @xmm_item_size)
				arg2 = Pointer.new(@args[1].mem, @args[1].pos + i * @xmm_item_size, @xmm_item_size)
				arr += dest.read
				arr += arg2.read
			end
			arr = (@func == "punpckl") ? arr.slice(0, @size) : arr.slice(@size, @size)
			@args[0].write arr
		when "pmovmsk"
			@args[0].write_with_zero_extension([])
			arr = @args[1].read.map{|x| x[7]}
			@args[0].write_bit_array(arr)
		when "pshuf"
			order = @args[2].read_int
			data = @args[1].read + Array.new(@xmm_item_size * 3){|x| 0}
			for i in 0..(@size / @xmm_item_size)
				dest = Pointer.new(@args[0].mem, @args[0].pos + i * @xmm_item_size, @xmm_item_size)
				shift = (order >> (2*i)) & 0b11
				dest.write data.slice(@xmm_item_size * (i + shift), @xmm_item_size)
			end
		when "pshufl"
			@func = "pshuf"
			execute
			@args[0].pointer_to_upper_half.write @args[1].pointer_to_upper_half.read
		when "pshufh"
			@func = "pshuf"
			execute
			@args[0].pointer_to_lower_half.write @args[1].pointer_to_lower_half.read
		else
			raise "function not implemented: " + @func
		end
	end
	
	def for_each_xmm_item(func)
		for i in 0..(@size / @xmm_item_size)
			dest_ptr = Pointer.new(@args[0].mem, @args[0].pos + i * @xmm_item_size, @xmm_item_size)
			arg_ptr  = Pointer.new(@args[1].mem, @args[1].pos + i * @xmm_item_size, @xmm_item_size)
			dest = dest_ptr.read_int
			arg = arg_ptr.read_int
			dest_ptr.write_int(func.call(dest, arg))
		end
	end
	
	def for_each_xmm_item_signed(func)
		for i in 0..(@size / @xmm_item_size)
			dest_ptr = Pointer.new(@args[0].mem, @args[0].pos + i * @xmm_item_size, @xmm_item_size)
			arg_ptr  = Pointer.new(@args[1].mem, @args[1].pos + i * @xmm_item_size, @xmm_item_size)
			dest = dest_ptr.read_int
			arg = arg_ptr.read_int
			dest_ptr.write_int(func.call(dest, arg))
		end
	end
	
	def for_each_xmm_item_and_constant(func)
		arg = @args[1].read_int
		for i in 0..(@size / @xmm_item_size)
			dest_ptr = Pointer.new(@args[0].mem, @args[0].pos + i * @xmm_item_size, @xmm_item_size)
			dest = dest_ptr.read_int
			dest_ptr.write_int(func.call(dest, arg))
		end	
	end

	def execute_string_instruction
		string_func = @func
		
		loop_mode = "none"
		if @prefix.repe
			if ["cmps", "scas"].include? string_func
				loop_mode = "repe"
			else
				loop_mode = "rep"
			end
		elsif @prefix.repne
			loop_mode = "repne"
		end

		loop do
			rax = Pointer.new(@cpu.register[0], 0, @size)
			rcx = Pointer.new(@cpu.register[1], 0, @size)
			rsi = Pointer.new(@cpu.register[6], 0, @address_size)
			rdi = Pointer.new(@cpu.register[7], 0, @address_size)

			# ES:EDI, DS:ESI. Only DS can be overridden.
			pointed_by_rdi = Pointer.new(@stream.mem, rdi.read_int % max_address, @size)
			pointed_by_rsi = Pointer.new(@stream.mem, (segment_offset + rsi.read_int) % max_address, @size)

			ptr_diff = @cpu.flags.d ? -@size : @size
		
			case string_func
			when "cmps"
				@func = "cmp"
				@args = [pointed_by_rdi, pointed_by_rsi]
				execute
				rdi.write_int(rdi.read_int + ptr_diff)
				rsi.write_int(rsi.read_int + ptr_diff)
			when "movs"
				pointed_by_rdi.write pointed_by_rsi.read
				rdi.write_int(rdi.read_int + ptr_diff)
				rsi.write_int(rsi.read_int + ptr_diff)
			when "lods"
				rax.write pointed_by_rsi.read
				rsi.write_int(rsi.read_int + ptr_diff)
			when "stos"
				pointed_by_rdi.write rax.read
				rdi.write_int(rdi.read_int + ptr_diff)
			when "scas"
				@func = "cmp"
				@args = [rax, pointed_by_rdi]
				execute
				rdi.write_int(rdi.read_int + ptr_diff)
			else
				raise "string function not implemented: " + string_func
			end
			
			# TODO: is RCX changed if there is no rep* prefix?
			unless loop_mode == "none"
				rcx.write_int(rcx.read_int - 1)
			end
			
			rcx_empty = rcx.read_int == 0
			
			case loop_mode
			when "none"
				break
			when "rep"
				break if rcx_empty
			when "repe"
				break if rcx_empty || !@cpu.flags.z
			when "repne"
				break if rcx_empty || @cpu.flags.z
			else
				raise "bad loop_mode: %s" % loop_mode
			end
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
		if @prefix.rex_w == 1
			return 8
		elsif @prefix.operand_size_overridden
			return 2
		else
			return 4
		end
	end
	
	def jump(pos)
		@cpu.rip = pos.read_int
	end
	
	@@reg_regmem_opcodes = {
		# format: opcode => [operation, is8bit, direction_bit]
		0x84 => ['test', 1, nil],
		0x85 => ['test', 0, nil],
		0x86 => ['xchg', 1, nil],
		0x87 => ['xchg', 0, nil],
		0x88 => ['mov', 1, 1],
		0x89 => ['mov', 0, 1],
		0x8A => ['mov', 1, 0],
		0x8B => ['mov', 0, 0],
		0x8D => ['lea', 0, 0],
		0x0FC0 => ['xadd', 1, 0],
		0x0FC1 => ['xadd', 0, 0],
		0x0FAF => ['imul', 0, 0],
		0x0FBC => ['bsf', 0, 0],
		0x0FBD => ['bsr', 0, 0],
	}
	
	@@mm_xmm_reg_regmem_opcodes = {
		# format: opcode => [operation, item size]
		0x0F60 => ['punpckl', 1],
		0x0F61 => ['punpckl', 2],
		0x0F62 => ['punpckl', 4],
		0x0F68 => ['punpckh', 1],
		0x0F69 => ['punpckh', 2],
		0x0F6A => ['punpckh', 4],
		0x0F74 => ['pcmpeq', 1],
		0x0F75 => ['pcmpeq', 2],
		0x0F76 => ['pcmpeq', 4],
		0x0FD4 => ['padd', 8],
		0x0FD8 => ['psubus', 1],
		0x0FD9 => ['psubus', 2],
		0x0FDA => ['pminu', 1],
		0x0FDB => ['pand', 8],
		0x0FDC => ['paddus', 1],
		0x0FDD => ['paddus', 2],
		0x0FDE => ['pmaxu', 1],
		0x0FDF => ['pandn', 1],
		0x0FE0 => ['pavg', 1],
		0x0FE3 => ['pavg', 2],
		0x0FEB => ['por', 8],
		0x0FEF => ['pxor', 8],
		0x0FF8 => ['psub', 1],
		0x0FF9 => ['psub', 2],
		0x0FFA => ['psub', 4],
		0x0FFB => ['psub', 8],
		0x0FFC => ['padd', 1],
		0x0FFD => ['padd', 2],
		0x0FFE => ['padd', 4],
	}

	@@mm_xmm_reg_regmem_opcodes_signed = {
		# format: opcode => [operation, item size]
		0x0F64 => ['pcmpgt', 1],
		0x0F65 => ['pcmpgt', 2],
		0x0F66 => ['pcmpgt', 4],
	}

	@@unified_opcode_table = {
		0x69 => ["imul", "size=2/4/8", "r", "r/m", "imm2/4"],
		0x6B => ["imul", "size=2/4/8", "r", "r/m", "imm1"],
		0x9E => ["sahf"],
		0x9F => ["lahf"],
		0xA8 => ["test", "size=1",     "acc", "imm1"],
		0xA9 => ["test", "size=2/4/8", "acc", "imm2/4"],
		0xC0 => ["#ROTATE/SHIFT", "size=1",     "r/m", "imm1"],
		0xC1 => ["#ROTATE/SHIFT", "size=2/4/8", "r/m", "imm1"],
		0xD0 => ["#ROTATE/SHIFT", "size=1",     "r/m", "const=1"],
		0xD1 => ["#ROTATE/SHIFT", "size=2/4/8", "r/m", "const=1"],
		0xD2 => ["#ROTATE/SHIFT", "size=1",     "r/m", "carry flag"],
		0xD3 => ["#ROTATE/SHIFT", "size=2/4/8", "r/m", "carry flag"],
		0xA4 => ["movs", "size=1"],
		0xA5 => ["movs", "size=2/4/8"],
		0xA6 => ["cmps", "size=1"],
		0xA7 => ["cmps", "size=2/4/8"],
		0xA8 => ["test", "size=1", "acc", "imm"],
		0xA9 => ["test", "size=2/4/8", "acc", "imm2/4"],
		0xAA => ["stos", "size=1"],
		0xAB => ["stos", "size=2/4/8"],
		0xAC => ["lods", "size=1"],
		0xAD => ["lods", "size=2/4/8"],
		0xAE => ["scas", "size=1"],
		0xAF => ["scas", "size=2/4/8"],
		0xF5 => ['cmc'],
		0xF8 => ['clc'],
		0xF9 => ['stc'],
		0xFA => ['cli'],
		0xFB => ['sti'],
		0xFC => ['cld'],
		0xFD => ['std'],
		0x0F05 => ["syscall"],
		0x0FA2 => ['cpuid'],
	}
end

class ModRM_Parser
	attr_accessor :operand_size

	def initialize(stream, prefix, cpu, operand_size, address_size, segment_offset)
		@prefix = prefix
		@stream = stream
		@modrm = stream.read
		@cpu = cpu
		@operand_size = operand_size
		@address_size = address_size
		@segment_offset = segment_offset
	end
	
	def mode
		return (@modrm >> 6) & 0x3
	end
	
	def opcode_ext
		return (@modrm & 0x38) >> 3
	end
	
	def register
		index = ((@modrm & 0x38) >> 3) + @prefix.reg_extension
		return Pointer.new(@cpu.register[index], 0, @operand_size)
	end
	
	def mm_or_xmm_register
		# TODO: add support of VEX/EVEX
		index = ((@modrm & 0x38) >> 3) + @prefix.reg_extension
		if @operand_size == 8
			return Pointer.new(@cpu.mm_register[index], 0, @operand_size)
		else
			return Pointer.new(@cpu.xmm_register[index], 0, @operand_size)
		end
	end
	
	def xmm_register
		# TODO: add support of VEX/EVEX
		index = ((@modrm & 0x38) >> 3) + @prefix.reg_extension
		return Pointer.new(@cpu.xmm_register[index], 0, @operand_size)
	end

	def register_or_memory
		regmem = (@modrm & 0x07) + 8 * @prefix.rex_b
		if mode == 0x03
			return Pointer.new(@cpu.register[regmem], 0, @operand_size)		
		else
			if [0x4, 0xC].include? regmem
				return sib
			elsif ([0x5, 0xD].include? regmem) && (mode == 0)
				rel = @stream.read_pointer(4).read_signed
				return memory_at(@cpu.rip + rel)
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

	def mm_or_xmm_register_or_memory
		# TODO: add support of VEX/EVEX
		regmem = (@modrm & 0x07) + 8 * @prefix.rex_b
		if mode == 0x03
			if @operand_size == 8
				return Pointer.new(@cpu.mm_register[regmem], 0, @operand_size)
			else
				return Pointer.new(@cpu.xmm_register[regmem], 0, @operand_size)
			end
		else
			# TODO: is pointer to memory stored in a general purpose register
			# or in MM/XMM register?
			return register_or_memory
		end
	end

	def xmm_register_or_memory
		# TODO: add support of VEX/EVEX
		regmem = (@modrm & 0x07) + 8 * @prefix.rex_b
		if mode == 0x03
			return Pointer.new(@cpu.xmm_register[regmem], 0, @operand_size)
		else
			# TODO: is pointer to memory stored in a general purpose register
			# or in MM/XMM register?
			return register_or_memory
		end
	end


	def memory_at(pos)
		p "memory_at %x" % pos
		# TODO: shall @segment_offset be used in all cases
		# TODO: how do segment overrides work with RIP addressing
		return Pointer.new(@stream.mem, (@segment_offset + pos) % (2 ** (8 * @address_size)), @operand_size) 
	end
	
	def disp32
		return @stream.read_pointer(4).read_signed
	end
	
	def disp8
		return @stream.read_pointer(1).read_signed
	end
	
	def sib
		sib = @stream.read
		@scale = 2 ** (sib >> 6)
		@index_reg = ((sib >> 3) & 0x07) + 8 * @prefix.rex_x
		@base_reg = (sib & 0x07) + 8 * @prefix.rex_b

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