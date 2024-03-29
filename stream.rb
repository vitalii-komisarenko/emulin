require_relative "addressable"
require_relative "pointer"

class Stream
    attr_accessor :pos
    attr_reader :mem

    def initialize(memory, pos)
        @mem = memory
        @pos = pos
    end
    
    def read()
        ret = @mem.read(@pos, 1)[0]
        @pos += 1
        return ret
    end
    
    def back()
        @pos -= 1
    end
    
    def read_pointer(size)
        res = Pointer.new(@mem, @pos, size)
        @pos += size
        return res
    end

    def read_signed_pointer(size)
        res = Pointer.new(@mem, @pos, size)
        @pos += size
        return res
    end
end