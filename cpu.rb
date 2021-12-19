require_relative "stream"
require_relative "instruction"
require_relative "register"
require_relative "stack"

class Cpu
    attr_reader :register, :mm_register, :xmm_register, :instructions_executed
    attr_writer :linux
    attr_accessor :stopped, :flags, :stack, :fs, :gs
    
    def initialize(mem, entry_point, stack_bottom)
        @register = []
        @mm_register = []
        @xmm_register = []
        @mem_stream = Stream.new(mem, entry_point)
        @stopped = false
        @flags = FlagsRegister.new
        @fs = 0
        @gs = 0
        @instructions_executed = 0
        for i in 0..15
            reg = Register.new
            reg.write(0, [0] * 8)
            reg.name = @@reg_names[i]
            @register.push reg
        end
        @stack = Stack.new(mem, @register[4])

        Pointer.new(@register[4], 0, 8).write_int(stack_bottom)
        Pointer.new(mem, stack_bottom, 8).write_int(1) # Hardcode argc = 1

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
        @instructions_executed += 1
        @flags.r = true
    end

    def rax=(value)
        @register[0].assign value
    end

    def rbx=(value)
        @register[3].assign value
    end

    def rcx=(value)
        @register[1].assign value
    end

    def rdx=(value)
        @register[2].assign value
    end

    def r11=(value)
        @register[11].assign value
    end

    # similar to `info registers` in GDB
    def to_s
        table = []

        for i in [0, 3, 1, 2, 6, 7, 5, 4] + (8..15).to_a
            value = @register[i].read_int(0, 8)

            table << [
                @register[i].name,
                "0x" + value.to_s(16),
                ([4, 5].include? i) ? "0x" + value.to_s(16) : [value].pack('Q').unpack('q').first.to_s
            ]
        end

        table << ["rip", "0x" + rip.to_s(16), "0x" + rip.to_s(16)]

        flags_arr = [
            [flags.c, 0x0001, "CF"],
            [flags.p, 0x0004, "PF"],
            [flags.a, 0x0010, "AF"],
            [flags.z, 0x0040, "ZF"],
            [flags.s, 0x0080, "SF"],
            [flags.i, 0x0200, "IF"],
            [flags.d, 0x0400, "DF"],
            [flags.o, 0x0800, "OF"],
            [flags.r, 0x10000, "RF"]
        ]

        flags_value = @instructions_executed > 0 ? 2 : 0
        flags_str_arr = []

        for i in flags_arr
            if i[0]
                flags_value += i[1]
                flags_str_arr << i[2]
            end
        end

        table << ["eflags", "0x" + flags_value.to_s(16), (["["] + flags_str_arr + ["]"]).join(" ")]

        table << ["cs", "0x33", "51"]
        table << ["ss", "0x2b", "43"]
        table << ["ds", "0x0", "0"]
        table << ["es", "0x0", "0"]
        table << ["fs", "0x" + @fs.to_s(16), @fs.to_s]
        table << ["gs", "0x" + @gs.to_s(16), @gs.to_s]

        res = "0x" + rip.to_s(16).rjust(16, '0') + "\n"
        for line in table
            res += line[0].ljust(15, ' ') + line[1].ljust(20, ' ') + line[2] + "\n"
        end

        for i in 0..15
            res += ("xmm%i" % i).ljust(15, ' ')
            for j in 0..15
                res += "0x" + @xmm_register[i].read(j, 1).first.to_s(16)
                res += ", " unless j == 15
            end
            res += "\n"
        end

        res
    end
end

class FlagsRegister
    attr_reader :o, :d, :i, :s, :z, :a, :p, :c, :r

    def initialize
        @o = false
        @d = false
        @i = true
        @s = false
        @z = false
        @a = false
        @p = false
        @c = false
        @r = false
    end

    # Flags are stored as booleans.
    # This method allows to write integers as flag value.
    def self.setter_wrapper(value)
        case value.class.name
        when "TrueClass", "FalseClass"
            return value
        when "Fixnum"
            return value == 0 ? false : true
        else
            raise "Unsupported class " + value.class.name + " value = " + value.to_s
        end
    end

    def o=(value)
        @o = self.class.setter_wrapper(value)
    end
    
    def d=(value)
        @d = self.class.setter_wrapper(value)
    end
    
    def i=(value)
        @i = self.class.setter_wrapper(value)
    end
    
    def s=(value)
        @s = self.class.setter_wrapper(value)
    end
    
    def z=(value)
        @z = self.class.setter_wrapper(value)
    end
    
    def a=(value)
        @a = self.class.setter_wrapper(value)
    end
    
    def p=(value)
        @p = self.class.setter_wrapper(value)
    end
    
    def c=(value)
        @c = self.class.setter_wrapper(value)
    end
    
    def r=(value)
        @r = self.class.setter_wrapper(value)
    end
end
