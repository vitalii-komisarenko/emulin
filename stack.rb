require_relative "pointer"

class Stack
    def initialize(mem, rsp)
        @mem = mem
        @rsp = Pointer.new(rsp, 0, 8)
    end
    
    def push(data)
        @rsp.write_int(@rsp.read_int - data.length)
        Pointer.new(@mem, @rsp.read_int, data.length).write(data)
    end
    
    def pop(size)
        ret = Pointer.new(@mem, @rsp.read_int, size).read
        @rsp.write_int(@rsp.read_int + size)
        return ret
    end
end
