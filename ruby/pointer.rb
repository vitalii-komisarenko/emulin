class Pointer
	def initialize(mem, pos, size)
		@mem = mem
		@pos = pos
		@size = size
	end
	
	def read
		@mem.read(@pos, @size)
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
end