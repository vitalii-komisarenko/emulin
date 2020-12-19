class Utils
	def self.resize(arr, size)
		if arr.length > size
			return arr.slice(0, size)
		elsif arr.length < size
			ret = arr
			while ret.length < size
				ret.push(0)
				return ret
			end
		else
			return arr
		end
	end
end