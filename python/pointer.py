from utils import Utils


class Pointer:
    def __init__(self, mem, pos, size):
        self.mem = mem
        self.pos = pos
        self.size = size

    def read(self):
        return self.mem.read(self.pos, self.size)

    def read_int(self):
        return self.mem.read_int(self.pos, self.size)

    def read_signed(self):
        return self.mem.read_int(self.pos, self.size)

    def read_bit_array(self):
        self.mem.read_bit_array(self.pos, self.size)

    def write_with_padding(self, data, padding):
        if len(data) < self.size:
            data += [padding] * (self.size - data.length)
        if len(data) > self.size:
            raise "Data does not fit into the buffer"
        self.mem.write(self.pos, data)

    def write_with_zero_extension(self, data):
        self.write_with_padding(data, 0)

    def write_with_sing_extension(self, data):
        padding = 0
        if data[-1] & 0x80:
            padding = 0xFF
        self.write_with_padding(data, padding)

    def write(self, data):
        # TODO: remove implicit size convertions in the program
        # and then rewrite this fucntion to check that size of
        # input is equal to the size of the buffer
        self.write_with_zero_extension(data)

    def write_bit_array(self, data):
        self.mem.write_bit_array(self.pos, data)

    def write_int(self, value):
        raise "not converted from ruby"
        # write([value].pack(pack_scheme).unpack("C*"))

    def debug_value(self):
        raise "not converted from ruby"
        # read.reverse.map{|x| "%02X" % x}.join(":")

    def pack_scheme(self):
        raise "not converted from ruby"
        # case @size
        # when 1
        #     return "C"
        # when 2
        #    return "S<"
        # when 4
        #     return "L<"
        # when 8
        #     return "Q<"
        # else
        #    raise "bad size: %d" % size
        # end

    def pack_scheme_signed(self):
        raise "not converted from ruby"
        # case @size
        # when 1
        #    return "c"
        # when 2
        #     return "s<"
        # when 4
        #    return "l<"
        # when 8
        #     return "q<"
        # else
        #     raise "bad size: %d" % size

    def highest_bit(self):
        return Utils.highest_bit(self.read_int(), self.size)

    def pointer_to_upper_half(self):
        if self.size % 2 != 0:
            raise "size is not even"
        return Pointer(self.mem, self.pos + self.size // 2, self.size // 2)

    def pointer_to_lower_half(self):
        if self.size % 2 != 0:
            raise "size is not even"
        return Pointer.new(self.mem, self.pos, self.size // 2)


class PointerSigned(Pointer):
    def read_int(self):
        return self.read_signed()
