from utils.operations import *


def sha256(m):

    assert isinstance(bytes(m, 'utf-8'), bytes)
    blocks = pad_message(bytes(m, 'utf-8'))
    prev_hash = digest_to_hex(HASH)

    for block in blocks:
        prev_hash = compression_function(prev_hash, block)
    return prev_hash


if __name__ == "__main__":
    # data = str()
    with open("input.txt", 'r') as file:
        data = file.read()
    msg = data
    print(msg)
    print(sha256(msg))
