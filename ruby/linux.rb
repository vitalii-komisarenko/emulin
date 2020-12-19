class Linux
	def initialize(cpu, mem)
		@cpu = cpu
		@mem = mem
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
				# return buffer size that was stored in %rdx
				@cpu.register[0].write(0, @cpu.register[2].read(0, 8))
			else
				raise "not implemented fd: %d" % fd
			end
		when 60 # exit
			puts "exit code: %d" % args[0]
			@cpu.stopped = true
		else
			raise "syscall not implemented: %d (0x%x)" % [number, number]
		end
	end
end