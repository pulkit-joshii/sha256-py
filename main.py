from utils.operations import *


def sha256(message):

    assert isinstance(bytes(message, 'utf-8'), bytes)
    blocks = pad_message(bytes(message, 'utf-8'))
    prev_hash = digest_to_hex(HASH)

    for block in blocks:
        prev_hash = compression_function(prev_hash, block)
    return prev_hash


if __name__ == "__main__":
    # data = str()
    file_path = input("File path:")
    with open(file_path, 'r') as file:
        data = file.read()
    msg = data
    print("----------------------------------------------------------------------------------------------------------")
    print("Input message:", msg)
    print("----------------------------------------------------------------------------------------------------------")
    print("Size of input message in bytes:", len(msg.encode('utf-8')))
    print("----------------------------------------------------------------------------------------------------------")
    print("Hash:", sha256(msg))
    print("----------------------------------------------------------------------------------------------------------")
    x = input("Press Enter to exit")
