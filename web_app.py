# web_app.py

import os
from flask import Flask, render_template, request, send_file

from bit_utils import bytes_to_hex, hex_to_bytes
from triple_des import triple_des_encrypt_bytes, triple_des_decrypt_bytes
from key_manager import generate_3des_key, save_key_to_file, load_key_from_file, list_keys
from file_handler import read_text_file, write_text_file

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
KEY_FILE = os.path.join(BASE_DIR, "keys.txt")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


@app.route("/")
def index():
    keys = list_keys(KEY_FILE)
    return render_template("index.html", keys=keys)


@app.route("/generate-key", methods=["POST"])
def generate_key():
    keynumber = request.form.get("keynumber", "").strip()
    seed_text = request.form.get("seed", "").strip()

    if not keynumber:
        return render_template("result.html", title="Lỗi", result="Thiếu keynumber")

    try:
        seed = int(seed_text)
    except ValueError:
        return render_template("result.html", title="Lỗi", result="Seed phải là số nguyên")

    try:
        key = generate_3des_key(seed)
        save_key_to_file(KEY_FILE, keynumber, key)
        return render_template(
            "result.html",
            title="Tạo khóa thành công",
            result=f"Đã lưu khóa với keynumber = {keynumber}"
        )
    except Exception as e:
        return render_template("result.html", title="Lỗi", result=str(e))


@app.route("/encrypt-text", methods=["POST"])
def encrypt_text():
    text = request.form.get("text_input", "")
    keynumber = request.form.get("keynumber", "").strip()

    if len(text) <= 15:
        return render_template("result.html", title="Lỗi", result="Chuỗi phải dài hơn 15 ký tự")

    try:
        key = load_key_from_file(KEY_FILE, keynumber)
        cipher = triple_des_encrypt_bytes(text.encode("utf-8"), key)
        cipher_hex = bytes_to_hex(cipher)

        output_path = os.path.join(OUTPUT_FOLDER, f"encrypted_text_{keynumber}.txt")
        write_text_file(output_path, cipher_hex)

        return render_template(
            "result.html",
            title="Kết quả mã hóa chuỗi",
            result=cipher_hex
        )
    except Exception as e:
        return render_template("result.html", title="Lỗi", result=str(e))


@app.route("/decrypt-text", methods=["POST"])
def decrypt_text():
    cipher_hex = request.form.get("text_input", "").strip()
    keynumber = request.form.get("keynumber", "").strip()

    try:
        key = load_key_from_file(KEY_FILE, keynumber)
        cipher_bytes = hex_to_bytes(cipher_hex)
        plain = triple_des_decrypt_bytes(cipher_bytes, key)
        plain_text = plain.decode("utf-8")

        output_path = os.path.join(OUTPUT_FOLDER, f"decrypted_text_{keynumber}.txt")
        write_text_file(output_path, plain_text)

        return render_template(
            "result.html",
            title="Kết quả giải mã chuỗi",
            result=plain_text
        )
    except Exception as e:
        return render_template("result.html", title="Lỗi", result=str(e))


@app.route("/encrypt-file", methods=["POST"])
def encrypt_file():
    keynumber = request.form.get("keynumber", "").strip()
    file = request.files.get("file_input")

    if not file or file.filename == "":
        return render_template("result.html", title="Lỗi", result="Chưa chọn file")

    try:
        key = load_key_from_file(KEY_FILE, keynumber)

        input_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(input_path)

        content = read_text_file(input_path)
        cipher = triple_des_encrypt_bytes(content.encode("utf-8"), key)
        cipher_hex = bytes_to_hex(cipher)

        output_filename = "encrypted_" + file.filename
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)
        write_text_file(output_path, cipher_hex)

        return send_file(output_path, as_attachment=True)
    except Exception as e:
        return render_template("result.html", title="Lỗi", result=str(e))


@app.route("/decrypt-file", methods=["POST"])
def decrypt_file():
    keynumber = request.form.get("keynumber", "").strip()
    file = request.files.get("file_input")

    if not file or file.filename == "":
        return render_template("result.html", title="Lỗi", result="Chưa chọn file")

    try:
        key = load_key_from_file(KEY_FILE, keynumber)

        input_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(input_path)

        cipher_hex = read_text_file(input_path).strip()
        plain = triple_des_decrypt_bytes(hex_to_bytes(cipher_hex), key)

        output_filename = "decrypted_" + file.filename
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(plain.decode("utf-8"))

        return send_file(output_path, as_attachment=True)
    except Exception as e:
        return render_template("result.html", title="Lỗi", result=str(e))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)