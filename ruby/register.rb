require_relative "addressable"

class Register < Addressable
	def check_addressing(pos, size)
		if (pos == 0) and [1, 2, 4, 8].include? size
			return
		end
		
		if (pos == 1) and (size == 1)
			return
		end
		
		raise "cannot read %d bytes from position %d" % [size, pos]
	end
	
	def write(pos, data)	
		check_addressing(pos, data.length)

		if (pos == 0) and (data.length == 4)
			# On x86_64 writing to the lowest 4 bytes of a register
			# clears the highest bytes
			data = [data[0], data[1], data[2], data[3], 0, 0, 0, 0]
		end
		
		super(pos, data)
	end
	
	def debug
		puts "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x" % [
			@mem.fetch(7, 0),
			@mem.fetch(6, 0),
			@mem.fetch(5, 0),
			@mem.fetch(4, 0),
			@mem.fetch(3, 0),
			@mem.fetch(2, 0),
			@mem.fetch(1, 0),
			@mem.fetch(0, 0),
		]
	end
end