require_relative "addressable"
require_relative "pointer"

class ConstBuffer < Addressable
	def initialize(value, size = 8)
		@in_init = true
		@size = size
		super()
		Pointer.new(self, 0, size).write_int(value)
		@name = "const"
		@in_init = false
	end
	
	def write(pos, data)
		unless @in_init
			raise "buffer is read-only"
		end
		
		super
	end
	
	def ptr
		return Pointer.new(self, 0, @size)
	end
end