class Addressable
	def initialize()
		@mem = {}
	end
	
	def read(pos, size)
		res = []
		for i in 0..size-1 do
			res.push(@mem.fetch(pos + i, 0))
		end
		res
	end
	
	def write(pos, data)
		for i in 0..data.length-1 do
			@mem[pos + i] = data[i]
		end
	end
	
	def read_int(pos, size)
		read(pos, size).pack("C*").unpack(pack_scheme(size))[0]
	end
	
	def read_signed(pos, size)
		read_int(pos, size) - 2 ** (8 * size)
	end

	def pack_scheme(size)
		case size
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
end