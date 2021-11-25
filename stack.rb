require_relative "pointer"

class Stack
    attr_reader :pos

    def initialize(mem, stack_buttom)
        @mem = mem
        @pos = stack_buttom
    end
    
    def push(data)
        @pos -= data.length
        Pointer.new(@mem, @pos, data.length).write(data)
    end
    
    def pop(size)
        ret = Pointer.new(@mem, @pos, size).read
        @pos += size
        return ret
    end
end