require_relative "stream"
require_relative "instruction"
require_relative "register"
require_relative "stack"

class Cpu
	attr_reader :register
	attr_writer :linux
	attr_accessor :stopped, :flags, :stack
	
	def initialize(mem, entry_point, stack_bottom)
		@register = []
		@mem_stream = Stream.new(mem, entry_point)
		@stopped = false
		@flags = FlagsRegister.new
		@stack = Stack.new(mem, stack_bottom)
		for i in 1..16
			reg = Register.new
			reg.write(0, [i, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
			@register.push reg
		end
	end
	
	def exectute_next_instruction
		instruction = Instruction.new(@mem_stream, self, @linux)
		instruction.execute
	end
end

class FlagsRegister
	def initialize
		@flags = {
			'o' => 0,
			'd' => 0,
			'i' => 0,
			's' => 0,
			'z' => 0,
			'a' => 0,
			'p' => 0,
			'c' => 0, 
		}
	end
	
	def get_flag(flag)
		@flags[flag]
	end
	
	def set_flag(flag, value)
		@flags[flag] = value
	end
	
	def to_s
		ret = ""
		for i in ['o', 'd', 'i', 's', 'z', 'a', 'p', 'c']
			ret += get_flag(i) == 1 ? i : '-'
		end
		return ret
	end
end