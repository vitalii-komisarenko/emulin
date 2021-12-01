require_relative "utils"

class Pointer
    attr_reader :mem, :pos
    attr_accessor :size, :read_size

    def initialize(mem, pos, size, read_size = nil)
        @mem = mem
        @pos = pos
        @size = size
        @read_size = read_size.nil? ? size : read_size
    end
    
    def read
        if @size == 0
            return []
        end
        data = @mem.read(@pos, @size)
        padding = data[data.length-1][7] == 1 ? 0xFF : 0
        return data + Array.new(@read_size - data.length, padding)
    end
    
    def read_int
        read.pack("C*").unpack(pack_scheme(read_size))[0]
    end
    
    def read_signed
        read.pack("C*").unpack(pack_scheme_signed(read_size))[0]
    end
    
    def read_bit_array
        @mem.read_bit_array(@pos, @size)
    end
    
    def write_with_padding(data, padding)
        if data.length < @size
            data += Array.new(@size - data.length, padding)
        end
        if data.length > @size
            raise "Data does not fit into the buffer"
        end
        @mem.write(@pos, data)
    end

    def write_with_zero_extension(data)
        write_with_padding(data, 0)
    end

    def write_with_sign_extension(data)
        padding = data[data.length-1][7] == 1 ? 0xFF : 0
        write_with_padding(data, padding)
    end
    
    def write(data)
        # TODO: remove implicit size convertions in the program
        # and then rewrite this fucntion to check that size of
        # input is equal to the size of the buffer
        write_with_sign_extension(data)
    end
    
    def write_bit_array(data)
        @mem.write_bit_array(@pos, data)
    end

    def write_int(value)
        write([value].pack(pack_scheme(size)).unpack("C*"))
    end
    
    def debug_value
        read.reverse.map{|x| "%02X" % x}.join(":")
    end
    
    def pack_scheme(size)
        case size
        when 1
            return "C"
        when 2
            return "S<"
        when 4
            return "L<"
        when 8
            return "Q<"
        else
            raise "bad size: %d" % size
        end
    end
    
    def pack_scheme_signed(size)
        case size
        when 1
            return "c"
        when 2
            return "s<"
        when 4
            return "l<"
        when 8
            return "q<"
        else
            raise "bad size: %d" % size
        end
    end
    
    def highest_bit_set
        return read_int & (2 ** (8 * @size - 1)) != 0
    end
    
    def highest_bit
        return highest_bit_set ? 1 : 0
    end

    def pointer_to_upper_half
        raise "size is not even" unless @size % 2 == 0
        return Pointer.new(@mem, @pos + @size / 2, @size / 2)
    end

    def pointer_to_lower_half
        raise "size is not even" unless @size % 2 == 0
        return Pointer.new(@mem, @pos, @size / 2)
    end
end

class PointerSigned < Pointer
    def read_int
        read_signed
    end
end
