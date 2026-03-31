# app_cli.py

from bit_utils import text_to_bytes, bytes_to_text, bytes_to_hex, hex_to_bytes
from triple_des import triple_des_encrypt_bytes, triple_des_decrypt_bytes
from key_manager import generate_3des_key, save_key_to_file, load_key_from_file, list_keys
from file_handler import read_text_file, write_text_file

KEY_FILE = "keys.txt"


def encrypt_text_flow():
    text = input("Nhap chuoi (>15 ky tu): ")
    if len(text) <= 15:
        print("Chuoi phai lon hon 15 ky tu")
        return

    keynumber = input("Nhap keynumber: ").strip()
    mode = input("1. Tao key moi | 2. Nap key tu file: ").strip()

    if mode == "1":
        seed = int(input("Nhap seed so nguyen: "))
        key = generate_3des_key(seed)
        save_key_to_file(KEY_FILE, keynumber, key)
        print("Da luu key vao keys.txt")
    else:
        key = load_key_from_file(KEY_FILE, keynumber)

    cipher = triple_des_encrypt_bytes(text_to_bytes(text), key)
    cipher_hex = bytes_to_hex(cipher)

    print("\nCipher (HEX):")
    print(cipher_hex)

    save_opt = input("Luu ciphertext ra file? (y/n): ").strip().lower()
    if save_opt == "y":
        out_file = input("Nhap ten file luu: ").strip()
        write_text_file(out_file, cipher_hex)
        print(f"Da luu ciphertext vao {out_file}")


def decrypt_text_flow():
    source = input("1. Nhap HEX truc tiep | 2. Doc tu file: ").strip()
    if source == "1":
        cipher_hex = input("Nhap ciphertext HEX: ").strip()
    else:
        in_file = input("Nhap file ciphertext: ").strip()
        cipher_hex = read_text_file(in_file).strip()

    keynumber = input("Nhap keynumber: ").strip()
    key = load_key_from_file(KEY_FILE, keynumber)

    plain = triple_des_decrypt_bytes(hex_to_bytes(cipher_hex), key)
    text = bytes_to_text(plain)

    print("\nPlaintext:")
    print(text)

    save_opt = input("Luu plaintext ra file? (y/n): ").strip().lower()
    if save_opt == "y":
        out_file = input("Nhap ten file luu: ").strip()
        write_text_file(out_file, text)
        print(f"Da luu plaintext vao {out_file}")


def encrypt_file_flow():
    in_path = input("Nhap duong dan file txt can ma hoa: ").strip()
    out_path = input("Nhap file output: ").strip()
    keynumber = input("Nhap keynumber: ").strip()

    mode = input("1. Tao key moi | 2. Nap key tu file: ").strip()
    if mode == "1":
        seed = int(input("Nhap seed so nguyen: "))
        key = generate_3des_key(seed)
        save_key_to_file(KEY_FILE, keynumber, key)
        print("Da luu key vao keys.txt")
    else:
        key = load_key_from_file(KEY_FILE, keynumber)

    content = read_text_file(in_path)
    cipher = triple_des_encrypt_bytes(content.encode("utf-8"), key)
    write_text_file(out_path, bytes_to_hex(cipher))
    print(f"Da ma hoa file -> {out_path}")


def decrypt_file_flow():
    in_path = input("Nhap file ciphertext HEX: ").strip()
    out_path = input("Nhap file output giai ma: ").strip()
    keynumber = input("Nhap keynumber: ").strip()

    key = load_key_from_file(KEY_FILE, keynumber)
    cipher_hex = read_text_file(in_path).strip()
    plain = triple_des_decrypt_bytes(hex_to_bytes(cipher_hex), key)
    write_text_file(out_path, plain.decode("utf-8"))
    print(f"Da giai ma file -> {out_path}")


def list_keys_flow():
    items = list_keys(KEY_FILE)
    if not items:
        print("Chua co khoa nao")
        return
    print("\nDanh sach khoa:")
    for item in items:
        print(f"- keynumber={item.get('keynumber')} ; key={item.get('key')}")


def main():
    while True:
        print("\n===== CHUONG TRINH 3DES =====")
        print("1. Ma hoa chuoi")
        print("2. Giai ma chuoi")
        print("3. Ma hoa file txt")
        print("4. Giai ma file txt")
        print("5. Xem danh sach key")
        print("0. Thoat")

        choice = input("Chon: ").strip()

        try:
            if choice == "1":
                encrypt_text_flow()
            elif choice == "2":
                decrypt_text_flow()
            elif choice == "3":
                encrypt_file_flow()
            elif choice == "4":
                decrypt_file_flow()
            elif choice == "5":
                list_keys_flow()
            elif choice == "0":
                break
            else:
                print("Lua chon khong hop le")
        except Exception as e:
            print("Loi:", e)


if __name__ == "__main__":
    main()