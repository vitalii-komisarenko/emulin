require_relative "utils"

class Pointer
	attr_reader :mem, :pos
	attr_accessor :size

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
		read.pack("C*").unpack(pack_scheme_signed)[0]
	end
	
	def read_bit_array
		@mem.read_bit_array(@pos, @size)
	end
	
	def write_with_padding(data, padding)
		if data.length < @size
			data += Array.new(@size - data.length, padding)
		end
		if data.length > @size
			raise "Data does not fit into the buffer"
		end
		@mem.write(@pos, data)
	end

	def write_with_zero_extension(data)
		write_with_padding(data, 0)
	end

	def write_with_sing_extension(data)
		padding = data[data.length-1][7] == 1 ? 0xFF : 0
		write_with_padding(data, padding)
	end
	
	def write(data)
		# TODO: remove implicit size convertions in the program
		# and then rewrite this fucntion to check that size of
		# input is equal to the size of the buffer
		write_with_zero_extension(data)
	end
	
	def write_bit_array(data)
		@mem.write_bit_array(@pos, data)
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
	
	def pack_scheme_signed
		case @size
		when 1
			return "c"
		when 2
			return "s<"
		when 4
			return "l<"
		when 8
			return "q<"
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

class PointerSigned < Pointer
	def read_int
		read_signed
	end
end