import struct
from pointer import Pointer


class Linux:
    def __init__(self, cpu, mem):
        self.cpu = cpu
        self.mem = mem

    def syscall_return_int(self, value):
        Pointer(self.cpu.register[0], 0, 8).write_int(value)

    def handle_syscall(self, number, args):
        if number == 1:  # write
            fd = args[0]
            pos = args[1]
            size = args[2]
            if fd == 1:  # stdout
                data = self.mem.read(pos, size)
                print(struct.pack('B' * size, data))
                self.syscall_return_int(size)
            else:
                raise "not implemented fd: %d" % fd
        elif number == 12:  # brk
            self.syscall_return_int(0)
        elif number == 60:  # exit
            print("exit code: %d" % args[0])
            self.cpu.stopped = True

        # getuid, getgid, geteuid, getegid
        elif number in [102, 104, 107, 108]:
            # 1000 is default UID of the first user on Ubuntu
            self.syscall_return_int(1000)
        else:
            raise "syscall not implemented: %d (0x%x)" % [number, number]
