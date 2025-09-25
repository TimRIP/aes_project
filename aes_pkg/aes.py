#Implementation of AES-128

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

S_BOX = []

#RCON

RCON = []

class AES:

    #Constructor only assigns the key and saves the computes the first round key
    def __init__(self, key: bytes):
        self.key = key
        #Compute the 11 round keys
        self.round_keys = self.key_expansion(key)

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
        return state
    
    #ShiftRows Operation (in-place)
    def shift_rows(self, state):
        return state
    
    #MixColumns Operation (in-place)
    def mix_columns(self, state):
        return state
    
    #AddRoundKey Operation (in-place)
    def add_round_key(self, state, round_key):
        #XOR operation between state and key
        return state

    #KeyExpansion Operation (in-place)
    def key_expansion(self, key):
        #Round keys are computed once and used for all blocks

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
        return 0
    
    def rotate_word (self, word):
        pass

    def sub_word_bytes(self, word):
        pass
    
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

    


    


    



