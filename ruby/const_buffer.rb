require_relative "addressable"
require_relative "pointer"

class ConstBuffer < Addressable
	def initialize(value)
		@in_init = true
		super()
		Pointer.new(self, 0, 8).write_int(value)
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
		return Pointer.new(self, 0, 8)
	end
end