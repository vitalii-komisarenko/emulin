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
end