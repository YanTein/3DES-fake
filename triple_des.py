# triple_des.py

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

    result = bytearray()
    for i in range(0, len(plain_data), 8):
        block = plain_data[i:i+8]
        b1 = des_encrypt_block(block, rk1)
        b2 = des_decrypt_block(b1, rk2)
        b3 = des_encrypt_block(b2, rk3)
        result.extend(b3)

    return bytes(result)


def triple_des_decrypt_bytes(cipher_data, master_key_24):
    if not isinstance(cipher_data, (bytes, bytearray)):
        raise TypeError("cipher_data phai la bytes hoac bytearray")
    if len(cipher_data) % 8 != 0:
        raise ValueError("Ciphertext khong hop le, do dai phai chia het cho 8")

    k1, k2, k3 = split_3des_key(master_key_24)

    rk1 = generate_des_round_keys(k1)
    rk2 = generate_des_round_keys(k2)
    rk3 = generate_des_round_keys(k3)

    result = bytearray()
    for i in range(0, len(cipher_data), 8):
        block = cipher_data[i:i+8]
        b1 = des_decrypt_block(block, rk3)
        b2 = des_encrypt_block(b1, rk2)
        b3 = des_decrypt_block(b2, rk1)
        result.extend(b3)

    return pkcs5_unpad(bytes(result))