from aes_pkg import AES
import argparse
import os


BLOCK_SIZE = 16

#Inserted into aes.py for message padding
def pkcs7_pad(message: bytes, bytes_per_block: int) -> bytes:
    """Return the message padded to a multiple of bytes_per_block."""
    remainder = len(message) % bytes_per_block
    padding_length = bytes_per_block - remainder if remainder != 0 else bytes_per_block
    padding = bytes([padding_length]) * padding_length
    return message + padding

def read_file_in_blocks(path: str) -> list[bytearray]:
    "opens the nice image of our Team and split it up in 16-byte blocks"
    with open(path, "rb") as f:
        data = f.read()

    blocks: list[bytearray] = []

    # append blocks of 16 bytes
    for i in range(0, len(data), BLOCK_SIZE):
        chunk = data[i:i+BLOCK_SIZE]        
        chunk = pkcs7_pad(chunk, BLOCK_SIZE)
        blocks.append(bytearray(chunk))

    return blocks

def read_file(path: str) -> bytes:
    "opens the nice image of our Team and returns its content"
    with open(path, "rb") as f:
        data = f.read()
    return data


def main(argv=None):
    """
    WE NEED TO CHANGE THIS So the arguments will refer to input Key and input file
    Also if it's a 128 and if it's more than 10 rounds
    p = argparse.ArgumentParser()
    p.add_argument("-n", "--name", default="World")
    args = p.parse_args(argv)
    print(f"Hello, {args.name}!")
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, "input.jpg")
    message = read_file(path)

    key = b"aaaabbbbccccdddd"
    aes = AES(key)
    #message = b"Jeg er Francesco ULLA"

    ciphertext = aes.encrypt_message(message)
    print("Ciphertext:", ciphertext)

    # we write the ciphertext to a file
    with open("ciphertext.enc", "wb") as f:
        f.write(ciphertext)

    plaintext = aes.decrypt_message(ciphertext)
    print("Plaintext:", plaintext)

if __name__ == "__main__":
    # kør: python -m aes_pkg.main eller aes
    main()