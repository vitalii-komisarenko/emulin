from addressable import Addressable


class Register(Addressable):
    @staticmethod
    def check_addressing(pos, size):
        if (pos == 0) and (size in [1, 2, 4, 8]):
            return

        if (pos == 1) and (size == 1):
            return

        raise "cannot read %d bytes from position %d" % [size, pos]

    def write(self, pos, data):
        self.check_addressing(pos, len(data))

        if (pos == 0) and (len(data) == 4):
            # On x86_64 writing to the lowest 4 bytes of a register
            # clears the highest bytes
            data = [data[0], data[1], data[2], data[3], 0, 0, 0, 0]

        super().write(pos, data)

    def debug(self):
        bytes = self.read(0, 8)
        print(':'.join(['{:02x}'.format(byte) for byte in reversed(bytes)]))


class MMRegister(Addressable):
    pass


class XMMRegister(Addressable):
    pass
