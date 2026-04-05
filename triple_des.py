# triple_des.py

import os

from bit_utils import pkcs5_pad, pkcs5_unpad
from key_schedule import generate_des_round_keys, split_3des_key
from des_core import des_encrypt_block, des_decrypt_block


def triple_des_encrypt_bytes(plain_data, master_key_24):
    if not isinstance(plain_data, (bytes, bytearray)):
        raise TypeError("plain_data phai la bytes hoac bytearray")

    plain_data = pkcs5_pad(plain_data)
    k1, k2, k3 = split_3des_key(master_key_24)

    rk1 = generate_des_round_keys(k1)
    rk2 = generate_des_round_keys(k2)
    rk3 = generate_des_round_keys(k3)

    iv = os.urandom(8)
    prev_block = iv
    result = bytearray(iv)
    for i in range(0, len(plain_data), 8):
        block = plain_data[i:i+8]
        block = bytes(a ^ b for a, b in zip(block, prev_block))
        b1 = des_encrypt_block(block, rk1)
        b2 = des_decrypt_block(b1, rk2)
        b3 = des_encrypt_block(b2, rk3)
        result.extend(b3)
        prev_block = b3

    return bytes(result)


def triple_des_decrypt_bytes(cipher_data, master_key_24):
    if not isinstance(cipher_data, (bytes, bytearray)):
        raise TypeError("cipher_data phai la bytes hoac bytearray")
    if len(cipher_data) < 16 or len(cipher_data) % 8 != 0:
        raise ValueError("Ciphertext CBC khong hop le")

    k1, k2, k3 = split_3des_key(master_key_24)

    rk1 = generate_des_round_keys(k1)
    rk2 = generate_des_round_keys(k2)
    rk3 = generate_des_round_keys(k3)

    iv = cipher_data[:8]
    ciphertext = cipher_data[8:]
    prev_block = iv
    result = bytearray()
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        b1 = des_decrypt_block(block, rk3)
        b2 = des_encrypt_block(b1, rk2)
        b3 = des_decrypt_block(b2, rk1)
        b3 = bytes(a ^ b for a, b in zip(b3, prev_block))
        result.extend(b3)
        prev_block = block

    return pkcs5_unpad(bytes(result))
