class mem:
	def __init__(self):
		self.mem = {}
		
	def get_byte(self, pos):
		if pos in self.mem:
			return self.mem[pos]
		else:
			return 0
			
	def set_byte(self, pos, value):
		self.mem[pos] = value
		
	def get_range(self, pos, length):
		res = []
		for i in range(length):
			res.append(self.get_byte(pos + i))
		return res
		
	def set_range(self, pos, values):
		for value in values:
			self.set_byte(pos, value)
			pos = pos + 1