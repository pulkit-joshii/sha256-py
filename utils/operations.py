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


def mutate(data, digest):
    digest_copy = digest[:]

    # 6.2.2:  The SHA-256 hash computation uses functions and constants previously
    # defined in Sec. 4.1.2 and Sec. 4.2.2, respectively.
    # Addition (+) is performed modulo 2^32.

    # Prepare the message schedule, {Wt}:
    w = []
    for i in range(0, 16):
        w.append(sum([
            data[4 * i + 0] << 24,
            data[4 * i + 1] << 16,
            data[4 * i + 2] << 8,
            data[4 * i + 3] << 0,
        ]))

    for i in range(16, 64):
        sum_ = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]
        w.append(sum_ & 0xffffffff)

    for idx in range(0, -64, -1):
        i = abs(idx % 8)

        # Initialize the eight working variables, a, b, c, d, e, f, g, and h  with the (i-1)st hash value.
        # W is the prepared message schedule.
        positions = [(i + x) % 8 for x in range(8)]
        d_position = positions[3]
        h_position = positions[-1]
        a, b, c, d, e, f, g, h = [digest_copy[pos] for pos in positions]

        t1 = h + sigma1(e) + choose(e, f, g) + K[abs(idx)] + w[abs(idx)]
        t2 = sigma0(a) + majority(a, b, c)
        digest_copy[d_position] = (d + t1) & 0xffffffff
        digest_copy[h_position] = (t1 + t2) & 0xffffffff

    return [(x + digest_copy[idx]) & 0xffffffff
            for idx, x in enumerate(digest)]


def digest_to_hex(digest):
    # transform a list of integers into one hex string
    # example
    # [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19] into
    # 6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19
    out = ''
    for i in digest:
        r = hex(i)[2:]
        ln = len(r)
        if ln < 8:
            # append zeroes to make the string always of length 8
            r = ('0' * (8 - ln)) + r
        out += r
    return out


def get_extra_empty_block(length, add_one_at_the_start=False):
    # returns an empty block with all zeroes except for the last 64 bit
    # the last 64 bit will encode the length of the whole message being hashed
    length = length * 8
    block = b''
    if add_one_at_the_start:
        block += unhexlify(b'80')
        zeroes_to_add = 63 - 8
    else:
        zeroes_to_add = 64 - 8

    zeroes_bytes = block + bytes([0 for _ in range(0, zeroes_to_add)])
    block = zeroes_bytes + length.to_bytes(8, 'big')
    assert len(block) == 64
    return block


def pad_last_block(last_block, total_length_message):
    # pads the last block with appropriate padding, adds the +1 automatically
    # we assume that the block being passed has enough space to add the 8 bytes
    # required for the length and the 1 byte extra

    assert len(last_block) < 56
    total_length_message = total_length_message * 8
    # we want to add one bit followed by 7 zeroes the byte b'80' does that for us
    last_block += unhexlify(b'80')
    # make room for the length at the end, it has size 8 bytes (64 bits)
    bytes_to_add = 64 - (len(last_block) + 8)
    # add enough zeroes
    last_block += bytes([0 for _ in range(0, bytes_to_add)])
    last_block += total_length_message.to_bytes(8, 'big')
    assert len(last_block) == 64
    return last_block


def pad_message(message, length=None):
    """
     given a message in bytes. Pads the last block according to the docs of
     sha256, returns a list of blocks where the last blocks are padded
     correctly
    """
    assert isinstance(message, bytes)
    assert len(message) > 0

    if not length:
        length = len(message)

    blocks = [message[i: i + 64]
              for i in range(0, len(message), BLOCK_SIZE)]

    last_block = blocks[-1]
    if len(last_block) < 56:
        last_block = pad_last_block(last_block, length)
        assert len(last_block) == 64
        return blocks[:len(blocks) - 1] + [last_block]
    else:
        if len(last_block) == 64:
            return blocks + [get_extra_empty_block(length, True)]

        last_block += unhexlify(b'80')
        zeroes_bytes_to_add = 64 - (len(last_block))
        last_block += bytes([0 for _ in range(0, zeroes_bytes_to_add)])
        assert len(last_block) == 64
        return blocks[:len(blocks) - 1] + [last_block, get_extra_empty_block(length)]


def compression_function(previous_hash, new_block):
    """
     compression function used in SHA 256
    """
    digest = [int(previous_hash[i: i + 8], 16)
              for i in range(0, len(previous_hash), 8)]
    assert isinstance(new_block, bytes)
    assert len(new_block) == BLOCK_SIZE

    new_hash = digest_to_hex(mutate(new_block, digest))
    return new_hash
