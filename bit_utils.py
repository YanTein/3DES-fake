# bit_utils.py

def text_to_bytes(text, encoding="utf-8"):
    if not isinstance(text, str):
        raise TypeError("text phai la str")
    return text.encode(encoding)


def bytes_to_text(data, encoding="utf-8"):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data phai la bytes hoac bytearray")
    return bytes(data).decode(encoding)


def bytes_to_bit_list(data):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data phai la bytes hoac bytearray")

    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def bit_list_to_bytes(bits):
    if not isinstance(bits, list):
        raise TypeError("bits phai la list")
    if len(bits) % 8 != 0:
        raise ValueError("Do dai bit list phai chia het cho 8")

    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            if bit not in (0, 1):
                raise ValueError("Bit phai la 0 hoac 1")
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def permute(bits, table):
    if not isinstance(bits, list):
        raise TypeError("bits phai la list")
    if not isinstance(table, list):
        raise TypeError("table phai la list")
    if not table:
        raise ValueError("table rong")
    if min(table) < 1:
        raise ValueError("Bang hoan vi phai danh so tu 1")
    if max(table) > len(bits):
        raise ValueError(
            f"Permute loi: max(table)={max(table)} > len(bits)={len(bits)}"
        )
    return [bits[i - 1] for i in table]


def xor_bits(a, b):
    if not isinstance(a, list) or not isinstance(b, list):
        raise TypeError("a va b phai la list")
    if len(a) != len(b):
        raise ValueError("xor_bits yeu cau hai list cung do dai")
    return [x ^ y for x, y in zip(a, b)]


def left_rotate(bits, n):
    if not isinstance(bits, list):
        raise TypeError("bits phai la list")
    if len(bits) == 0:
        return []
    n = n % len(bits)
    return bits[n:] + bits[:n]


def split_list(data, size):
    if size <= 0:
        raise ValueError("size phai > 0")
    return [data[i:i+size] for i in range(0, len(data), size)]


def join_lists(blocks):
    result = []
    for block in blocks:
        result.extend(block)
    return result


def pkcs_pad(data, block_size=8):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data phai la bytes hoac bytearray")
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size khong hop le")
    pad_len = block_size - (len(data) % block_size)
    return bytes(data) + bytes([pad_len] * pad_len)


def pkcs_unpad(data, block_size=8):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data phai la bytes hoac bytearray")
    if not data:
        raise ValueError("Du lieu rong")
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size khong hop le")

    data = bytes(data)
    pad_len = data[-1]

    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Padding khong hop le")
    if len(data) < pad_len:
        raise ValueError("Padding khong hop le")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding khong hop le")

    return data[:-pad_len]


def pkcs5_pad(data):
    return pkcs_pad(data, 8)


def pkcs5_unpad(data):
    return pkcs_unpad(data, 8)


def bytes_to_hex(data):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data phai la bytes hoac bytearray")
    hex_chars = "0123456789ABCDEF"
    result = []
    for b in data:
        result.append(hex_chars[(b >> 4) & 0xF])
        result.append(hex_chars[b & 0xF])
    return "".join(result)


def hex_to_bytes(hex_str):
    if not isinstance(hex_str, str):
        raise TypeError("hex_str phai la chuoi")

    hex_str = hex_str.strip().replace(" ", "").replace("\n", "").replace("\r", "").upper()
    if len(hex_str) == 0:
        return b""
    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string khong hop le")

    def hex_val(ch):
        if '0' <= ch <= '9':
            return ord(ch) - ord('0')
        if 'A' <= ch <= 'F':
            return ord(ch) - ord('A') + 10
        raise ValueError(f"Ky tu hex khong hop le: {ch}")

    out = bytearray()
    for i in range(0, len(hex_str), 2):
        hi = hex_val(hex_str[i])
        lo = hex_val(hex_str[i + 1])
        out.append((hi << 4) | lo)
    return bytes(out)