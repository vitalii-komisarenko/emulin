import unittest


class Utils:
    def resize(arr, size):
        if len(arr) > size:
            return arr[:size]
        elif len(arr) < size:
            return arr + [0] * (size - len(arr))
        else:
            return arr

    def highest_bit(value, size):
        """
        Extract the highest bit of the interger of given size

        :param value: the integer value. Negative values accepted
        :param size: number of bytes in the binary representation
        :returns: the highest bit -- 1 or 0
        :raises ValueError: interger value cannot be represented using given
            number of bytes
        """
        overflow = False
        if value > 256 ** size:
            overflow = True
        if value < -((256 ** size) // 2):
            overflow = True

        if overflow:
            raise ValueError(f"value {value} does not fit into {size} byte(s)")

        if value < 0:
            return True

        while size > 1:
            value //= 256
            size -= 1

        return (value & 0x80) >> 7


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

    def test_higher_bit(self):
        # basic checks
        self.assertEqual(Utils.highest_bit(0x80, 1), 1)
        self.assertEqual(Utils.highest_bit(0x80, 2), 0)

        # check long numbers (more than 8 bytes)
        self.assertEqual(Utils.highest_bit(0xFF00FF00FF00FF00FF00, 10), 1)
        self.assertEqual(Utils.highest_bit(0x7FFF00FF00FF00FF00FF00, 11), 0)

        # check negative numbers
        self.assertEqual(Utils.highest_bit(-1, 1), 1)
        self.assertEqual(Utils.highest_bit(-0x80, 1), 1)
        self.assertEqual(Utils.highest_bit(-0x80, 2), 1)
