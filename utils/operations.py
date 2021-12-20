from binascii import unhexlify

from constants import *


def shift_right(x, n):
    """
    right shift operation, where x is a w-bit word and n is an integer with 0 ≤ n < w
    """
    return (x & 0xffffffff) >> n


def rotate_right(x, y):
    """
    circular right shift operation, where x is a w-bit word and n is an integer with 0 ≤ n < w.
    """
    return (((x & 0xffffffff) >> (y & 31)) | (x << (BITS_IN_WORD - (y & 31)))) & 0xffffffff


def choose(x, y, z):
    """
    Ch(x,y,z)=(x & y) ^ (¬x & z)
    """
    return z ^ (x & (y ^ z))


def majority(x, y, z):
    """
    Maj(x, y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ ( y ∧ z)
    """
    return ((x | y) & z) | (x & y)


def sigma0(x):
    """
    sigma0(x) = right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)
    """
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)


def sigma1(x):
    """
    sigma1(x) = right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)
    """
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)


def gamma0(x):
    """
    gamma0(x) = right_rotate(x, 7) ^ right_rotate(x, 18) ^ right_shift(x, 3)
    """
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ shift_right(x, 3)


def gamma1(x):
    """
    gamma1(x) = right_rotate(x, 17) ^ right_rotate(x, 19) ^ right_shift(x, 10)
    """
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ shift_right(x, 10)
