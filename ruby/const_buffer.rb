require_relative "addressable"
require_relative "pointer"

class ConstBuffer < Addressable
	def initialize(value)
		Pointer.new(@mem, 0, 8).write_int(value)
	end
	
	def write(pos, data)
		raise "buffer is read-only"
	end
end