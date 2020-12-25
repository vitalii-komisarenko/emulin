require_relative "utils"

class Pointer
	attr_reader :size, :mem, :pos

	def initialize(mem, pos, size)
		@mem = mem
		@pos = pos
		@size = size
	end
	
	def read
		@mem.read(@pos, @size)
	end
	
	def read_int
		read.pack("C*").unpack(pack_scheme)[0]
	end
	
	def read_signed
		read_int - 2 ** (8 * @size - 1)
	end
	
	def write(data)
		if data.length < @size
			data += Array.new(@size - data.length, 0)
		end
		if data.length > @size
			data = data.slice(0, @size)
		end
		@mem.write(@pos, data)
	end
	
	def write_int(value)
		write([value].pack(pack_scheme).unpack("C*"))
	end
	
	def debug_value
		read.reverse.map{|x| "%02X" % x}.join(":")
	end
	
	def pack_scheme
		case @size
		when 1
			return "C"
		when 2
			return "S<"
		when 4
			return "L<"
		when 8
			return "Q<"
		else
			raise "bad size: %d" % size
		end
	end
	
	def highest_bit_set
		return read_int & (2 ** (8 * @size - 1)) != 0
	end
	
	def highest_bit
		return highest_bit_set ? 1 : 0
	end
end