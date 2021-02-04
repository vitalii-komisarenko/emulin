import unittest


class Utils:
    def resize(arr, size):
        if len(arr) > size:
            return arr[:size]
        elif len(arr) < size:
            return arr + [0] * (size - len(arr))
        else:
            return arr

    def highest_bit_set(value, size):
        overflow = False
        if value > 256 ** size:
            overflow = True
        if value < -((256 ** size) // 2):
            overflow = True

        if overflow:
            raise f"value {value} does not fit into {size} byte(s)"

        if value < 0:
            return True

        while size > 1:
            value //= 256
            size -= 1

        return value & 0x80


class TestUtils(unittest.TestCase):
    def test_resize(self):
        # increase size
        arr1 = [3, 2, 1]
        arr1_resized = Utils.resize(arr1, 6)
        self.assertListEqual(arr1, [3, 2, 1])
        self.assertListEqual(arr1_resized, [3, 2, 1, 0, 0, 0])

        # decrease size
        arr2 = [3, 2, 1]
        arr2_resized = Utils.resize(arr2, 2)
        self.assertListEqual(arr2, [3, 2, 1])
        self.assertListEqual(arr2_resized, [3, 2])

        # same size
        arr3 = [3, 2, 1]
        arr3_resized = Utils.resize(arr3, 3)
        self.assertListEqual(arr3, [3, 2, 1])
        self.assertListEqual(arr3_resized, [3, 2, 1])

    def test_highest_bit_set(self):
        # basic checks
        self.assertTrue(Utils.highest_bit_set(0x80, 1))
        self.assertFalse(Utils.highest_bit_set(0x80, 2))

        # check long numbers (more than 8 bytes)
        self.assertTrue(Utils.highest_bit_set(0xFF00FF00FF00FF00FF00, 10))
        self.assertFalse(Utils.highest_bit_set(0x7FFF00FF00FF00FF00FF00, 11))

        # check negative numbers
        self.assertTrue(Utils.highest_bit_set(-1, 1))
        self.assertTrue(Utils.highest_bit_set(-0x80, 1))
        self.assertTrue(Utils.highest_bit_set(-0x80, 2))
