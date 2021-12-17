class Addressable
    attr_accessor :name

    @@MAX_ADDR = 2 ** 64

    def initialize()
        @mem = {}
        @name = "???"
    end

    def read(pos, size)
        res = []
        for i in 0..size-1 do
            res.push(@mem.fetch((pos + i) % @@MAX_ADDR, 0))
        end
        res
    end

    def read_bit_array(pos, size)
        byte_arr = read(pos, size)
        return byte_arr.flat_map{|byte|
            [byte[0], byte[1], byte[2], byte[3],
             byte[4], byte[5], byte[6], byte[7]]}
    end

    def write(pos, data)
        for i in 0..data.length-1 do
            @mem[(pos + i) % @@MAX_ADDR] = data[i]
        end
    end

    def write_null_terminated_string(pos, str)
        arr = str.bytes + [0]
        write(pos, arr)
        return pos + arr.length
    end

    def write_bit_array(pos, bitarray)
        raise "Bit array does not map to byte array" unless bitarray.length % 8 == 0
        arr_of_bit_arr = *bitarray.each_slice(8)
        byte_arr = []
        for i in 0..(arr_of_bit_arr.length-1)
            item = arr_of_bit_arr[i]
            byte = item[0] + 2 * item[1] + 4 * item[2] + 8 * item[3] +
                16 * item[4] + 32 * item[5] + 64 * item[6] + 128 * item[7]
            byte_arr.push byte
        end
        write(pos, byte_arr)
    end

    def write_int(pos, size, value)
        data = [value].pack(pack_scheme(size)).unpack("C*")
        write(pos, data)
    end

    def read_int(pos, size)
        read(pos, size).pack("C*").unpack(pack_scheme(size))[0]
    end

    def read_signed(pos, size)
        read_int(pos, size) - 2 ** (8 * size)
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
end
