# key_schedule.py

from bit_utils import bytes_to_bit_list, permute, left_rotate
from des_tables import PC1, PC2, SHIFT_TABLE


def normalize_des_key(key8):
    if not isinstance(key8, (bytes, bytearray)):
        raise TypeError("key8 phai la bytes hoac bytearray")
    if len(key8) != 8:
        raise ValueError("Moi khoa DES phai dai 8 byte")
    return bytes(key8)


def generate_des_round_keys(key8):
    key8 = normalize_des_key(key8)
    key_bits = bytes_to_bit_list(key8)

    permuted = permute(key_bits, PC1)  # 64 -> 56
    c = permuted[:28]
    d = permuted[28:]

    round_keys = []
    for shift in SHIFT_TABLE:
        c = left_rotate(c, shift)
        d = left_rotate(d, shift)
        cd = c + d
        round_key = permute(cd, PC2)   # 56 -> 48
        round_keys.append(round_key)

    return round_keys


def split_3des_key(master_key_24):
    if not isinstance(master_key_24, (bytes, bytearray)):
        raise TypeError("master_key_24 phai la bytes hoac bytearray")
    if len(master_key_24) != 24:
        raise ValueError("Khoa 3DES phai dai 24 byte")
    master_key_24 = bytes(master_key_24)
    return master_key_24[0:8], master_key_24[8:16], master_key_24[16:24]