# key_manager.py

from bit_utils import bytes_to_hex, hex_to_bytes


class SimpleLCG:
    def __init__(self, seed=123456789):
        self.state = int(seed) & 0x7FFFFFFF

    def next_byte(self):
        self.state = (1103515245 * self.state + 12345) & 0x7FFFFFFF
        return self.state & 0xFF


def generate_3des_key(seed=123456789):
    rng = SimpleLCG(seed)
    key = bytearray()
    for _ in range(24):
        key.append(rng.next_byte())
    return bytes(key)


def save_key_to_file(filename, keynumber, key_bytes):
    if not keynumber:
        raise ValueError("keynumber khong duoc rong")
    if len(key_bytes) != 24:
        raise ValueError("key_bytes phai dai 24 byte")

    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"keynumber={keynumber};key={bytes_to_hex(key_bytes)}\n")


def load_key_from_file(filename, keynumber):
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split(";")
            kv = {}
            for p in parts:
                k, v = p.split("=", 1)
                kv[k.strip()] = v.strip()

            if kv.get("keynumber") == str(keynumber):
                key = hex_to_bytes(kv["key"])
                if len(key) != 24:
                    raise ValueError("Khoa trong file khong hop le")
                return key

    raise ValueError("Khong tim thay keynumber")


def list_keys(filename):
    items = []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(";")
                kv = {}
                for p in parts:
                    k, v = p.split("=", 1)
                    kv[k.strip()] = v.strip()
                items.append(kv)
    except FileNotFoundError:
        return []
    return items