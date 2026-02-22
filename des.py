"""
DES (Data Encryption Standard) Algorithm Implementation
========================================================

A complete implementation of the DES block cipher as defined in FIPS 46-3.

DES operates on 64-bit blocks using a 56-bit key (supplied as 64 bits with
8 parity bits). It performs 16 rounds of a Feistel network, each using a
different 48-bit subkey derived from the original key.

Usage:
    python des.py
"""


# ─────────────────────────── Permutation Tables ───────────────────────────

# Initial Permutation (IP) — applied to the 64-bit plaintext block
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Final (Inverse) Permutation (IP⁻¹)
IP_INV = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
]

# Expansion Permutation (E) — expands 32-bit half-block to 48 bits
E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

# Permutation (P) — applied after S-box substitution
P = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
]

# S-Boxes (S1 through S8) — each maps 6 bits → 4 bits
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 2, 0, 14, 9, 11],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


# ──────────────────────── Key Schedule Tables ─────────────────────────

# Permuted Choice 1 (PC-1) — selects 56 bits from the 64-bit key
PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

# Permuted Choice 2 (PC-2) — selects 48 bits from the 56-bit key state
PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Number of left shifts per round during key scheduling
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


# ─────────────────────── Helper Functions ─────────────────────────

def string_to_bits(text: str) -> list[int]:
    """Convert a string to a list of bits (MSB first for each byte)."""
    bits = []
    for char in text:
        byte = ord(char)
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_string(bits: list[int]) -> str:
    """Convert a list of bits back to a string."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        chars.append(chr(byte))
    return "".join(chars)


def hex_to_bits(hex_str: str) -> list[int]:
    """Convert a hex string to a list of bits."""
    bits = []
    for ch in hex_str:
        val = int(ch, 16)
        for i in range(3, -1, -1):
            bits.append((val >> i) & 1)
    return bits


def bits_to_hex(bits: list[int]) -> str:
    """Convert a list of bits to a hex string."""
    hex_str = ""
    for i in range(0, len(bits), 4):
        nibble = 0
        for bit in bits[i:i + 4]:
            nibble = (nibble << 1) | bit
        hex_str += format(nibble, "x")
    return hex_str


def permute(block: list[int], table: list[int]) -> list[int]:
    """Apply a permutation table to a block of bits."""
    return [block[pos - 1] for pos in table]


def left_shift(bits: list[int], n: int) -> list[int]:
    """Circular left shift a bit list by n positions."""
    return bits[n:] + bits[:n]


def xor(bits_a: list[int], bits_b: list[int]) -> list[int]:
    """XOR two equal-length bit lists."""
    return [a ^ b for a, b in zip(bits_a, bits_b)]


# ─────────────────────── Key Schedule ─────────────────────────────

def generate_subkeys(key_bits: list[int]) -> list[list[int]]:
    """
    Generate 16 round subkeys (each 48 bits) from the 64-bit key.

    Steps:
      1. Apply PC-1 to reduce the key to 56 bits.
      2. Split into two 28-bit halves (C and D).
      3. For each round, left-shift C and D by the schedule amount,
         then apply PC-2 to produce a 48-bit subkey.
    """
    # Apply PC-1
    key56 = permute(key_bits, PC1)

    # Split into left (C) and right (D) halves
    C, D = key56[:28], key56[28:]

    subkeys = []
    for round_num in range(16):
        # Left-shift both halves
        C = left_shift(C, SHIFT_SCHEDULE[round_num])
        D = left_shift(D, SHIFT_SCHEDULE[round_num])

        # Combine and apply PC-2 to get the 48-bit subkey
        combined = C + D
        subkey = permute(combined, PC2)
        subkeys.append(subkey)

    return subkeys


# ──────────────── Feistel Function (f) ────────────────────────────

def feistel(right_half: list[int], subkey: list[int]) -> list[int]:
    """
    The Feistel (f) function used in each DES round.

    Steps:
      1. Expand the 32-bit right half to 48 bits using E.
      2. XOR with the 48-bit round subkey.
      3. Split into 8 groups of 6 bits; each group goes through
         one S-box to produce 4 bits.
      4. Concatenate the 32 output bits and apply permutation P.
    """
    # Step 1: Expansion
    expanded = permute(right_half, E)

    # Step 2: XOR with subkey
    xored = xor(expanded, subkey)

    # Step 3: S-box substitution
    sbox_output = []
    for i in range(8):
        chunk = xored[i * 6:(i + 1) * 6]

        # Row = outer two bits (bit 0 and bit 5)
        row = (chunk[0] << 1) | chunk[5]
        # Column = inner four bits (bits 1-4)
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]

        # Look up the S-box value
        val = S_BOXES[i][row][col]

        # Convert 4-bit value to bits
        for j in range(3, -1, -1):
            sbox_output.append((val >> j) & 1)

    # Step 4: Permutation P
    return permute(sbox_output, P)


# ──────────────────── Core DES Block Processing ──────────────────

def des_block(block_bits: list[int], subkeys: list[int]) -> list[int]:
    """
    Encrypt or decrypt a single 64-bit block.

    For encryption, pass subkeys in order [0..15].
    For decryption, pass subkeys in reverse order [15..0].
    """
    # Initial Permutation
    block = permute(block_bits, IP)

    # Split into 32-bit halves
    left, right = block[:32], block[32:]

    # 16 Feistel rounds
    for i in range(16):
        f_result = feistel(right, subkeys[i])
        new_right = xor(left, f_result)
        left = right
        right = new_right

    # Combine halves (note: final swap — right before left)
    combined = right + left

    # Final Permutation (IP⁻¹)
    return permute(combined, IP_INV)


# ──────────────────── Padding (PKCS#5) ────────────────────────────

def pad(data: str) -> str:
    """Apply PKCS#5 padding to make data a multiple of 8 bytes."""
    pad_len = 8 - (len(data) % 8)
    return data + chr(pad_len) * pad_len


def unpad(data: str) -> str:
    """Remove PKCS#5 padding."""
    pad_len = ord(data[-1])
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


# ──────────────────── Public API ──────────────────────────────────

def des_encrypt(plaintext: str, key: str) -> str:
    """
    Encrypt plaintext using DES in ECB mode.

    Args:
        plaintext: The message to encrypt (any length).
        key: An 8-character (64-bit) key string.

    Returns:
        Hex-encoded ciphertext string.
    """
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 characters (64 bits)")

    key_bits = string_to_bits(key)
    subkeys = generate_subkeys(key_bits)

    # Pad plaintext to a multiple of 8 bytes
    plaintext = pad(plaintext)

    ciphertext_hex = ""
    # Process each 64-bit (8-byte) block
    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i + 8]
        block_bits = string_to_bits(block)
        encrypted_bits = des_block(block_bits, subkeys)
        ciphertext_hex += bits_to_hex(encrypted_bits)

    return ciphertext_hex


def des_decrypt(ciphertext_hex: str, key: str) -> str:
    """
    Decrypt a hex-encoded ciphertext using DES in ECB mode.

    Args:
        ciphertext_hex: Hex-encoded ciphertext string.
        key: An 8-character (64-bit) key string.

    Returns:
        Decrypted plaintext string with padding removed.
    """
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 characters (64 bits)")

    key_bits = string_to_bits(key)
    subkeys = generate_subkeys(key_bits)

    # Reverse subkeys for decryption
    subkeys_reversed = subkeys[::-1]

    plaintext = ""
    # Process each 64-bit (16 hex characters) block
    for i in range(0, len(ciphertext_hex), 16):
        block_hex = ciphertext_hex[i:i + 16]
        block_bits = hex_to_bits(block_hex)
        decrypted_bits = des_block(block_bits, subkeys_reversed)
        plaintext += bits_to_string(decrypted_bits)

    return unpad(plaintext)


# ──────────────────── NIST Validation & Demo ──────────────────────

def nist_test():
    """
    Verify against a known DES test vector.
    Key:        0E329232EA6D0D73
    Plaintext:  8787878787878787
    Ciphertext: 0000000000000000
    """
    key_bits = hex_to_bits("0E329232EA6D0D73")
    plaintext_bits = hex_to_bits("8787878787878787")
    expected = "0000000000000000"

    subkeys = generate_subkeys(key_bits)
    cipher_bits = des_block(plaintext_bits, subkeys)
    result = bits_to_hex(cipher_bits)

    print("=" * 55)
    print("         DES Test Vector Validation")
    print("=" * 55)
    print(f"  Key        : 0E329232EA6D0D73")
    print(f"  Plaintext  : 8787878787878787")
    print(f"  Expected   : {expected}")
    print(f"  Got        : {result}")
    print(f"  Status     : {'✅ PASSED' if result == expected else '❌ FAILED'}")
    print()

    # Also verify decryption
    subkeys_rev = subkeys[::-1]
    decrypted_bits = des_block(cipher_bits, subkeys_rev)
    dec_result = bits_to_hex(decrypted_bits)
    print(f"  Decrypted  : {dec_result}")
    print(f"  Matches PT : {'✅ PASSED' if dec_result == '8787878787878787' else '❌ FAILED'}")
    print("=" * 55)


def demo():
    """Demonstrate DES encryption and decryption with a text message."""
    key = "SECRET_K"
    message = "Hello, DES encryption!"

    print()
    print("=" * 55)
    print("            DES Encryption Demo")
    print("=" * 55)
    print(f"  Key        : {key}")
    print(f"  Plaintext  : {message}")

    encrypted = des_encrypt(message, key)
    print(f"  Ciphertext : {encrypted}")

    decrypted = des_decrypt(encrypted, key)
    print(f"  Decrypted  : {decrypted}")
    print(f"  Match      : {'✅ SUCCESS' if decrypted == message else '❌ FAILURE'}")
    print("=" * 55)


if __name__ == "__main__":
    nist_test()
    demo()
