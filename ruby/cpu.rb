require_relative "stream"
require_relative "instruction"
require_relative "register"

class Cpu
	attr_reader :register
	attr_writer :linux
	
	def initialize(mem, entry_point)
		@register = []
		@mem_stream = Stream.new(mem, entry_point)
		for i in 1..16
			@register.push Register.new
		end
	end
	
	def exectute_next_instruction
		instruction = Instruction.new(@mem_stream, self, @linux)
		instruction.execute
	end
end