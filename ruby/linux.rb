class Linux
	def initialize(cpu, mem)
		@cpu = cpu
		@mem = mem
	end
	
	def syscall_return_int(value)
		Pointer.new(@cpu.register[0], 0, 8).write_int value
	end

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
		when 60 # exit
			puts "exit code: %d" % args[0]
			@cpu.stopped = true
		when 102, 104, 107, 108 # getuid, getgid, geteuid, getegid
			syscall_return_int 1000 # default UID of the first user on Ubuntu
		else
			raise "syscall not implemented: %d (0x%x)" % [number, number]
		end
	end
end