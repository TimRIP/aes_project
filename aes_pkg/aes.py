#Implementation of AES-128
from typing import List
from unittest import case

#Algorithm Steps
"""
Preliminary 
0) Choose the key
1) Generate round keys with key expansion
2) Pad the plaintext and divide into blocks

For each block:
3) Add corresponding round key

For 9 rounds:
4) SubBytes
5) ShiftRows
6) MixColumns
7) AddRoundKey

In the 10th and final round:
8) SubBytes
9) ShiftRows
10) AddRoundKey

The block is now encrypted
Append all blocks to get the ciphertext


"""

#Constants
BLOCK_SIZE = 16

#NOTES
#State and Words are temporary, they do not constitue class fields

#Byte substitution table - constructed with multiplicative inverse of each byte in the
# finite field GF(2^8) + Affine transformation

#Here we do not construct it from stratch. Instead, we will perform SubBytes operation 
# by simply retrieving values from the table

#AES works on bytes(8 bits)so 0x63 = 0110 0011, 0x7c = 0111 1100, 0x77 = 0111 011, 
# so Writing them in hex makes it easy to see the structure
#Each entry is a byte (0–255) written in hex.
#So 0x63 is the hex representation of 99 in decimal
#The table is indexed by hex coordinates (x, y).
#For example: x = 0, y = 0 → 0x63. Next: x = 0, y = 1 → 0x7c., x = 0, y = 2 → 0x77. and so on

S_BOX = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]


# inverse S-Box for InvSubBytes step
INV_S_Box = [0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d]

#RCON : for 10 round constant in aes-128, words with first byte non-zero 
# The RC values come from successive powers of 2 in GF(2^8)
#RC[i]=2i ^−1mod(x^8+x^4+x^3+x+1)

RCON = [ [0x01,0x00,0x00,0x00],
    [0x02,0x00,0x00,0x00],
    [0x04,0x00,0x00,0x00],
    [0x08,0x00,0x00,0x00],
    [0x10,0x00,0x00,0x00],
    [0x20,0x00,0x00,0x00],
    [0x40,0x00,0x00,0x00],
    [0x80,0x00,0x00,0x00],
    [0x1B,0x00,0x00,0x00],
    [0x36,0x00,0x00,0x00]]

MIX_COL_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

# we rotate 1 bit to the left then look at first bit 
# if it is 1 we need to xor with 0x1B (which is the modolus x^8 + x^4 + x^3 + x + 1)
# otherwise we do nothing (ie xor with 0x00)
def Xtime(a: int) -> int:
    return ( (a << 1) & 0xFF ) ^ (0x1B if (a & 0x80) else 0x00)

def GF_mul(a: int, b: int) -> int :
    if (b == 1):
        return a
    elif (b == 2):
        return Xtime(a)
    elif (b == 3):
        return Xtime(a) ^ a # multiply by 3 is (2·x) ⊕ x
    else:
        assert False, "Unsupported multiplication in GF(2^8)"
        return 0    

class AES:

    #Constructor only assigns the key and saves the computes the first round key
    def __init__(self, key: bytes):
        if len(key) != BLOCK_SIZE: ## which is 16 bytes for AES-128
            raise ValueError("Key must be 16 bytes (128 bits) long.")
        self.key = key
        self.round_keys = self.key_expansion(key) #list of 11 round keys

    #ENCRYPT
    def encrypt_message(self, message:bytes) -> bytes:
        #Adds padding through pad_message
        data = self.pad_message(bytes(message))
        out = bytearray()
        for i in range(0, len(data), BLOCK_SIZE):
            out.extend(self.encrypt_block(data[i:i+BLOCK_SIZE]))
        return bytes(out)
    
    #DECRYPT
    def decrypt_message(self, ciphertext:bytes) -> bytes:
        #Iterates through blocks to encrypt each one of them
        #Removes the padding
        return 0
    
    #Helpers

    def encrypt_block(self, block:bytes) -> bytes:

        #block into a 4x4
        state = self.bytes_to_state(block)

        #Initial AddRoundKey
        self.add_round_key(state, self.round_keys[0])

        for round in range(1, 10):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, self.round_keys[round])
        #Final round (no MixColumns)
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, self.round_keys[10])
        #state back to bytes
        out = self.state_to_bytes(state)

        return out

    def decrypt_block(self, block:bytes) -> bytes:
        return 0
    
    #Necessitates of final variable defining the block size
    #Use pcks7_pad in the naive approach processing all the blocks at once
    def pad_message(self, message:bytes) -> bytes:

        #Compute how many bytes are used in the last block
        remainder = len(message) % BLOCK_SIZE

        #Calculate the padding length as the difference between the block size and the bytes used
        #If the message has a length multiple of BLOCK_SIZE we need to add an entire empty block 
        padding_length = BLOCK_SIZE - remainder if remainder != 0 else BLOCK_SIZE


        #The length in bytes is converted in bits
        padding = bytes([padding_length]) * padding_length

        return message + padding
    
    #Core transformations

    #SubBytes Operation (in-place)
    def sub_bytes(self, state):
        for r in range(4):  #row
            for c in range(4):  #column
                byte = state[r][c]
                state[r][c] = S_BOX[byte]  # substitute byte using S-Box
        return state
    
    def shift_rows(self, state):
        # Row 0: unchanged

        # Row 1: rotate left by 1
        a, b, c, d = state[1]
        state[1] = [b, c, d, a]

        # Row 2: rotate left by 2
        a, b, c, d = state[2]
        state[2] = [c, d, a, b]

        # Row 3: rotate left by 3 (== right by 1)
        a, b, c, d = state[3]
        state[3] = [d, a, b, c]

        return state
    

    def mix_columns(self, state):

        for c in range(4):  # for each column
            a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
            state[0][c] = GF_mul(a0, MIX_COL_MATRIX[0][0]) ^ GF_mul(a1, MIX_COL_MATRIX[0][1]) ^ GF_mul(a2, MIX_COL_MATRIX[0][2]) ^ GF_mul(a3, MIX_COL_MATRIX[0][3])
            state[1][c] = GF_mul(a0, MIX_COL_MATRIX[1][0]) ^ GF_mul(a1, MIX_COL_MATRIX[1][1]) ^ GF_mul(a2, MIX_COL_MATRIX[1][2]) ^ GF_mul(a3, MIX_COL_MATRIX[1][3])
            state[2][c] = GF_mul(a0, MIX_COL_MATRIX[2][0]) ^ GF_mul(a1, MIX_COL_MATRIX[2][1]) ^ GF_mul(a2, MIX_COL_MATRIX[2][2]) ^ GF_mul(a3, MIX_COL_MATRIX[2][3])
            state[3][c] = GF_mul(a0, MIX_COL_MATRIX[3][0]) ^ GF_mul(a1, MIX_COL_MATRIX[3][1]) ^ GF_mul(a2, MIX_COL_MATRIX[3][2]) ^ GF_mul(a3, MIX_COL_MATRIX[3][3])

        return state
  
    #AddRoundKey Operation (in-place)
    def add_round_key(self, state, round_key):
        # round_key is 16 bytes → applied byte by byte

        #XOR operation between state and round_key
        for c in range(4):  # column
            for r in range(4):  # row
                state[r][c] ^= round_key[c * 4 + r]
        return state

    def key_expansion(self, key: bytes):
        """
        1) Initialize the first 4 words (W[0..3]) directly from the key
        2) For words W[i] where i >= 4:
        a) If i mod 4 == 0:
          - Rotate the previous word (rotate_word)
          - Substitute bytes using S-Box (sub_words)
          - XOR with RCON[i//4 - 1]
       b) Otherwise:
          - XOR the previous word with the word 4 positions earlier
        3) Repeat until 44 words are generated (11 round keys × 4 words each)
        4) Each round key is 4×4 bytes, used in AddRoundKey for encryption and decryption.
        """
        # 44 words, each word = 4 bytes (list[int])
        words = []
        # W[0..3] from the key (column-major: bytes 0..3, 4..7, 8..11, 12..15)
        for i in range(4):
            words.append([key[4*i + 0], key[4*i + 1], key[4*i + 2], key[4*i + 3]])

        # Expand to W[4..43]
        for i in range(4, 44):
            temp = words[i - 1][:]
            if i % 4 == 0:
                temp = self.rotate_word(temp)          # rotate bytes left by 1
                temp = self.sub_word_bytes(temp)       # S-Box on each byte
                temp[0] ^= RCON[(i // 4) - 1][0]          # XOR first byte with round constant
            # W[i] = W[i-4] XOR temp
            words.append([(words[i - 4][j] ^ temp[j]) & 0xFF for j in range(4)])

        # Pack 44 words into 11 round keys (each 4 words = 16 bytes), column by column
        round_keys = []
        for r in range(11):
            rk_bytes = []
            for c in range(4):
                rk_bytes.extend(words[4*r + c])  # append the whole column (rows 0..3)
            round_keys.append(bytes(rk_bytes))   # bytes or list[int] both work with your add_round_key

        return round_keys  # list of 11 items; each item is 16 bytes (flat, column-major)

    def rotate_word(self, word):
        # word: [b0, b1, b2, b3]  ->  [b1, b2, b3, b0]
        return word[1:] + word[:1]

    def sub_word_bytes(self, word):
        # Apply S-Box to each byte
        return [S_BOX[b] for b in word]
    
    #Helpers

    def bytes_to_state(self, block: bytes):
        return [[block[r + 4 * c] for c in range(4)] for r in range(4)]

    def state_to_bytes(self, state):
        return bytes([state[r][c] for c in range(4) for r in range(4)])



    #Algorithm Steps – Decryption
    """
    Preliminary 
    0) Choose the key
    1) Generate round keys with key expansion (same as encryption)
    2) Divide the ciphertext into 16-byte blocks

    For each block:
    3) Add corresponding round key (from the last round)

    For 9 rounds (rounds 9 → 1):
    4) Inverse ShiftRows
    5) Inverse SubBytes
    6) AddRoundKey
    7) Inverse MixColumns

    In the 10th and final round:
    8) Inverse ShiftRows
    9) Inverse SubBytes
    10) AddRoundKey (from the first round)

    The block is now decrypted
    Append all blocks to get the plaintext
    Remove padding from the last block
    """

    # PKCS#7 padding removal
    def unpad_message(self, message: bytes) -> bytes:
        # Get the last byte to determine padding length
        padding_length = message[-1]
        # Remove padding bytes and return
        return message[:-padding_length]

    # SubBytes inverse (in-place)
    def inv_sub_bytes(self, state):
        # Apply inverse S-box on each byte of the state
        return state

    # ShiftRows inverse (in-place)
    def inv_shift_rows(self, state):
        # Rotate rows of the state in the opposite direction
        return state

    # MixColumns inverse (in-place)
    def inv_mix_columns(self, state):
        # Apply inverse MixColumns transformation
        return state

    


    


    



