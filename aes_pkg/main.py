from aes_pkg import Aes
import argparse
import os


BLOCK_SIZE = 16

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


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("-n", "--name", default="World")
    args = p.parse_args(argv)
    print(f"Hello, {args.name}!")
    
    greeter = Aes("yahhh this works")
    print(greeter.respond())

    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, "input.jpg")
    blocks = read_file_in_blocks(path)

    print(f"Read {len(blocks)} blocks from input.jpg")

if __name__ == "__main__":
    # kør: python -m aes_pkg.main eller aes
    main()