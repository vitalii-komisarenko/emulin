require_relative "stream"
require_relative "pointer"

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
	attr_reader :function, :destination, :arguments
	def initialize(stream, cpu)
		@cpu = cpu
		@prefix = InstructionPrefix.new(stream)
		@rex = REX.new(stream)
		@opcode = read_opcode(stream)
		case @opcode
		when 0xb8..0xbf
			reg = @opcode - 0xb8 + 8 * @rex.b
			size = multi_byte_operand_size
			@function = "mov"
			@destination = Pointer.new(@cpu.register[reg], 0, size)
			@arguments = [ stream.read_pointer(size) ]
		else
			raise "not implemented: opcode 0x%x" % @opcode
		end
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
		puts @function
		if @function == "mov"
			puts "OK"
			@destination.write @arguments[0].read
		else
			raise "unsupported function: " + @function
		end
	end

	
	def multi_byte_operand_size
		if @rex.w == 1
			return 8
		elsif @prefix.operand_size_overridden
			return 2
		else
			return 4
		end
	end
end

class ModRM_Parser
	def initialize(stream, rex, cpu)
		@rex = rex
		@stream = stream
		@modrm = stream.read
		@cpu = cpu
	end
	
	def mode
		return (@modrm >> 6) & 0x3
	end
	
	def opcode_ext
		return (@modrm & 0x38) >> 3
	end
	
	def register
		index = ((@modrm & 0x38) >> 3) + 8 * rex.r
		return @cpu.register[index]
	end
	
	def rm
		if mode == 0x3
			return @cpu.register[index]
		else
			raise "mode not implemented %d" % mode
		end
	end
end