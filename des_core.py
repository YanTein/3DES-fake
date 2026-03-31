# des_core.py

from bit_utils import (
    bytes_to_bit_list,
    bit_list_to_bytes,
    permute,
    xor_bits,
)
from des_tables import IP, FP, E, P, SBOX


def sbox_substitution(bits48):
    if not isinstance(bits48, list):
        raise TypeError("bits48 phai la list")
    if len(bits48) != 48:
        raise ValueError("SBOX input phai dai 48 bit")

    out = []
    for i in range(8):
        block = bits48[i * 6:(i + 1) * 6]
        if len(block) != 6:
            raise ValueError("Moi block SBOX phai dai 6 bit")

        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]

        value = SBOX[i][row][col]

        out.extend([
            (value >> 3) & 1,
            (value >> 2) & 1,
            (value >> 1) & 1,
            value & 1
        ])

    return out


def feistel_function(r32, round_key48):
    if len(r32) != 32:
        raise ValueError("r32 phai dai 32 bit")
    if len(round_key48) != 48:
        raise ValueError("round_key48 phai dai 48 bit")

    expanded = permute(r32, E)         # 32 -> 48
    mixed = xor_bits(expanded, round_key48)
    substituted = sbox_substitution(mixed)  # 48 -> 32
    return permute(substituted, P)     # 32 -> 32


def des_encrypt_block(block8, round_keys):
    if not isinstance(block8, (bytes, bytearray)):
        raise TypeError("block8 phai la bytes hoac bytearray")
    if len(block8) != 8:
        raise ValueError("Block DES phai dai 8 byte")
    if len(round_keys) != 16:
        raise ValueError("DES can 16 round keys")

    bits = bytes_to_bit_list(block8)   # 64 bit
    bits = permute(bits, IP)

    l = bits[:32]
    r = bits[32:]

    for i in range(16):
        new_l = r
        f_out = feistel_function(r, round_keys[i])
        new_r = xor_bits(l, f_out)
        l, r = new_l, new_r

    final_bits = permute(r + l, FP)
    return bit_list_to_bytes(final_bits)


def des_decrypt_block(block8, round_keys):
    if len(round_keys) != 16:
        raise ValueError("DES can 16 round keys")
    return des_encrypt_block(block8, round_keys[::-1])