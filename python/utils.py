class Utils:
    def resize(arr, size):
        if len(arr) > size:
            return arr[:size]
        elif len(arr) < size:
            ret = arr
            while len(ret) < size:
                ret.append(0)
                return ret
        else:
            return arr

    def highest_bit_set(value, size):
        return value & (1 << (8 ** size - 1))
