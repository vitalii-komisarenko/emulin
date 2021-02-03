require_relative "stream"
require_relative "instruction"
require_relative "register"
require_relative "stack"

class Cpu
	attr_reader :register, :mm_register, :xmm_register
	attr_writer :linux
	attr_accessor :stopped, :flags, :stack, :mem_stream, :fs, :gs
	
	def initialize(mem, entry_point, stack_bottom)
		@register = []
		@mm_register = []
		@xmm_register = []
		@mem_stream = Stream.new(mem, entry_point)
		@stopped = false
		@flags = FlagsRegister.new
		@stack = Stack.new(mem, stack_bottom)
		@fs = 0
		@gs = 0
		for i in 0..15
			reg = Register.new
			reg.write(0, [i, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
			reg.name = "reg #%d %s" % [i, @@reg_names[i]]
			@register.push reg
		end

		for i in 0..31
			reg = MMRegister.new
			reg.name = "mm #%d" % i
			@mm_register.push reg
		end

		for i in 0..31
			reg = XMMRegister.new
			reg.name = "xmm #%d" % i
			@xmm_register.push reg
		end
	end
	
	@@reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

	def rip
		return @mem_stream.pos
	end

	def rip=(new_rip)
		@mem_stream.pos = new_rip
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