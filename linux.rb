class Linux
    def initialize(cpu, mem)
        @cpu = cpu
        @mem = mem
        @brk = 0x5d8000
    end
    
    def syscall_return_int(value)
        @cpu.rax = value
    end

    # Values of rcx and r11 are not preserved during syscall
    # In this method they are assigned to hardcoded values
    # in order to have output closer to GDB output.
    def handle_syscall(number, args)
        case number
        when 1 # write
            fd = args[0]
            pos = args[1]
            size = args[2]
            if fd == 1 # stdout
                data = @mem.read(pos, size)
                print data.pack("C*")
                syscall_return_int size
            else
                raise "not implemented fd: %d" % fd
            end
        when 12 # brk
            if args[0] > 0
                @brk = args[0]
            end
            @cpu.rcx = 0x54a2ab
            syscall_return_int @brk
        when 60 # exit
            puts "exit code: %d" % args[0]
            @cpu.stopped = true
        when 102, 104, 107, 108 # getuid, getgid, geteuid, getegid
            syscall_return_int 1000 # default UID of the first user on Ubuntu
        when 158
            code = args[0]
            case code
            when 0x1002
                @cpu.fs = args[1]
                @cpu.rcx = 0x4a8fe7
                @cpu.r11 = 0x302
                syscall_return_int 0
            when 0x3001
                @cpu.rcx = 0x4a86ef
                @cpu.r11 = 0x346
                syscall_return_int -22 # EINVAL
            else
                raise "Not implemented. Code = 0x%x" % code
            end
        else
            raise "syscall not implemented: %d (0x%x)" % [number, number]
        end
    end
end
