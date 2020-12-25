require_relative "stream"
require_relative "instruction"
require_relative "register"
require_relative "stack"

class Cpu
	attr_reader :register
	attr_writer :linux
	attr_accessor :stopped, :flags, :stack, :mem_stream
	
	def initialize(mem, entry_point, stack_bottom)
		@register = []
		@mem_stream = Stream.new(mem, entry_point)
		@stopped = false
		@flags = FlagsRegister.new
		@stack = Stack.new(mem, stack_bottom)
		for i in 1..16
			reg = Register.new
			reg.write(0, [i, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
			reg.name = "reg #%d" % (i - 1)
			@register.push reg
		end
	end
	
	def exectute_next_instruction
		instruction = Instruction.new(@mem_stream, self, @linux)
		instruction.execute
	end
end

class FlagsRegister
	attr_accessor :o, :d, :i, :s, :z, :a, :p, :c

	def initialize
		@o = false
		@d = false
		@i = false
		@s = false
		@z = false
		@a = false
		@p = false
		@c = false
	end
	
	def to_s
		ret = ""
		ret += @o ? 'o' : '-'
		ret += @d ? 'd' : '-'
		ret += @i ? 'i' : '-'
		ret += @s ? 's' : '-'
		ret += @z ? 'z' : '-'
		ret += @a ? 'a' : '-'
		ret += @p ? 'p' : '-'
		ret += @c ? 'c' : '-'
		return ret
	end
end