import struct


class Addressable:
    MAX_ADDR = 2 ** 64

    def __init__(self):
        self.mem = {}
        self.name = "???"

    def read(self, pos, size):
        res = []
        for i in range(size):
            res.push(self.mem.get((pos + i) % self.MAX_ADDR, 0))

        return res

    def read_bit_array(self, pos, size):
        byte_arr = self.read(pos, size)
        res = []
        for byte in byte_arr:
            res.append(byte & 0b00000001)
            res.append((byte & 0b00000010) >> 1)
            res.append((byte & 0b00000100) >> 2)
            res.append((byte & 0b00001000) >> 3)
            res.append((byte & 0b00010000) >> 4)
            res.append((byte & 0b00100000) >> 5)
            res.append((byte & 0b01000000) >> 6)
            res.append((byte & 0b10000000) >> 7)

        return res

    def write(self, pos, data):
        for i in len(data):
            self.mem[(pos + i) % self.MAX_ADDR] = data[i]

    def write_bit_array(self, pos, bitarray):
        if len(bitarray) % 8 != 0:
            raise "Bit array does not map to byte array"

        byte_arr = []

        for byte_start in bitarray[::8]:
            byte = bitarray[byte_start]
            byte += bitarray[byte_start + 1] << 1
            byte += bitarray[byte_start + 2] << 2
            byte += bitarray[byte_start + 3] << 3
            byte += bitarray[byte_start + 4] << 4
            byte += bitarray[byte_start + 5] << 5
            byte += bitarray[byte_start + 6] << 6
            byte += bitarray[byte_start + 7] << 7

            byte_arr.append(byte)

        self.write(pos, byte_arr)

    def read_int(self, pos, size):
        byte_arr = self.read(pos, size)
        string = struct.pack("B" * size, byte_arr)
        return struct.unpack(string, self.pack_scheme(size))[0]

    def read_signed(self, pos, size):
        byte_arr = self.read(pos, size)
        string = struct.pack("B" * size, byte_arr)
        return struct.unpack(string, self.pack_scheme(size).lower())[0]

    def pack_scheme(size):
        if size == 1:
            return "B"
        elif size == 2:
            return "<H"
        elif size == 4:
            return "<I"
        elif size == 8:
            return "<Q"
        else:
            raise "bad size: %d" % size
