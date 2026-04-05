# web_app.py

import os
import time
from flask import Flask, render_template, request, send_file

from bit_utils import bytes_to_hex, hex_to_bytes, bytes_to_base64, base64_to_bytes
from triple_des import (
    triple_des_encrypt_bytes, triple_des_decrypt_bytes,
    triple_des_encrypt_cbc, triple_des_decrypt_cbc,
)
from key_manager import generate_3des_key, save_key_to_file, load_key_from_file, list_keys
from file_handler import read_text_file, write_text_file

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
KEY_FILE = os.path.join(BASE_DIR, "keys.txt")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _encode_cipher(data, encoding):
    return bytes_to_base64(data) if encoding == "base64" else bytes_to_hex(data)

def _decode_cipher(text, encoding):
    return base64_to_bytes(text) if encoding == "base64" else hex_to_bytes(text)

def _fmt_time(seconds):
    ms = seconds * 1000
    if ms < 1:    return f"{ms * 1000:.2f} µs"
    if ms < 1000: return f"{ms:.3f} ms"
    return f"{seconds:.3f} s"

def _cbc_encrypt(plain_bytes, key):
    """Sinh IV ngẫu nhiên, mã hóa CBC, trả về [IV 8 byte] + [ciphertext]."""
    iv = os.urandom(8)
    return iv + triple_des_encrypt_cbc(plain_bytes, key, iv)

def _cbc_decrypt(data, key):
    """Tách 8 byte IV đầu, giải mã phần còn lại."""
    if len(data) < 9:
        raise ValueError("Dữ liệu CBC không hợp lệ (thiếu IV)")
    return triple_des_decrypt_cbc(data[8:], key, data[:8])


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", keys=list_keys(KEY_FILE))


@app.route("/generate-key", methods=["POST"])
def generate_key():
    keynumber = request.form.get("keynumber", "").strip()
    seed_text  = request.form.get("seed", "").strip()

    if not keynumber:
        return render_template("result.html", title="Lỗi", result="Thiếu keynumber")

    seed = None
    if seed_text:
        try:
            seed = int(seed_text)
        except ValueError:
            return render_template("result.html", title="Lỗi", result="Seed phải là số nguyên")

    try:
        key = generate_3des_key(seed)
        save_key_to_file(KEY_FILE, keynumber, key)
        seed_info = f"seed = {seed}" if seed is not None else "random (os.urandom)"
        return render_template(
            "result.html",
            title="Tạo khóa thành công",
            result=f"Keynumber : {keynumber}\nSinh khóa : {seed_info}"
        )
    except Exception as e:
        return render_template("result.html", title="Lỗi", result=str(e))


@app.route("/encrypt-text", methods=["POST"])
def encrypt_text():
    text      = request.form.get("text_input", "")
    keynumber = request.form.get("keynumber", "").strip()
    mode      = request.form.get("mode", "ECB")
    encoding  = request.form.get("encoding", "base64")

    if len(text) <= 15:
        return render_template("result.html", title="Lỗi", result="Chuỗi phải dài hơn 15 ký tự")

    try:
        key = load_key_from_file(KEY_FILE, keynumber)
        plain_bytes = text.encode("utf-8")

        t0 = time.perf_counter()
        raw = _cbc_encrypt(plain_bytes, key) if mode == "CBC" else triple_des_encrypt_bytes(plain_bytes, key)
        elapsed = time.perf_counter() - t0

        cipher_str = _encode_cipher(raw, encoding)
        write_text_file(os.path.join(OUTPUT_FOLDER, f"encrypted_text_{keynumber}.txt"), cipher_str)

        return render_template(
            "result.html",
            title=f"Mã hóa chuỗi ({mode} / {encoding.upper()})",
            result=cipher_str,
            elapsed=_fmt_time(elapsed),
            input_size=len(plain_bytes),
            output_size=len(raw),
        )
    except Exception as e:
        return render_template("result.html", title="Lỗi", result=str(e))


@app.route("/decrypt-text", methods=["POST"])
def decrypt_text():
    cipher_str = request.form.get("text_input", "").strip()
    keynumber  = request.form.get("keynumber", "").strip()
    mode       = request.form.get("mode", "ECB")
    encoding   = request.form.get("encoding", "base64")

    try:
        key = load_key_from_file(KEY_FILE, keynumber)
        raw = _decode_cipher(cipher_str, encoding)

        t0 = time.perf_counter()
        plain = _cbc_decrypt(raw, key) if mode == "CBC" else triple_des_decrypt_bytes(raw, key)
        elapsed = time.perf_counter() - t0

        plain_text = plain.decode("utf-8")
        write_text_file(os.path.join(OUTPUT_FOLDER, f"decrypted_text_{keynumber}.txt"), plain_text)

        return render_template(
            "result.html",
            title=f"Giải mã chuỗi ({mode} / {encoding.upper()})",
            result=plain_text,
            elapsed=_fmt_time(elapsed),
            input_size=len(raw),
            output_size=len(plain),
        )
    except Exception as e:
        return render_template("result.html", title="Lỗi", result=str(e))


@app.route("/encrypt-file", methods=["POST"])
def encrypt_file():
    keynumber = request.form.get("keynumber", "").strip()
    mode      = request.form.get("mode", "ECB")
    file      = request.files.get("file_input")

    if not file or file.filename == "":
        return render_template("result.html", title="Lỗi", result="Chưa chọn file")

    try:
        key = load_key_from_file(KEY_FILE, keynumber)
        input_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(input_path)
        plain_bytes = open(input_path, "rb").read()

        t0 = time.perf_counter()
        raw = _cbc_encrypt(plain_bytes, key) if mode == "CBC" else triple_des_encrypt_bytes(plain_bytes, key)
        elapsed = time.perf_counter() - t0

        base_name = os.path.splitext(file.filename)[0]
        output_filename = f"encrypted_{mode}_{base_name}.bin"
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)
        with open(output_path, "wb") as f:
            f.write(raw)

        resp = send_file(output_path, as_attachment=True,
                         download_name=output_filename,
                         mimetype="application/octet-stream")
        resp.headers["X-Elapsed"]     = _fmt_time(elapsed)
        resp.headers["X-Input-Size"]  = str(len(plain_bytes))
        resp.headers["X-Output-Size"] = str(len(raw))
        return resp
    except Exception as e:
        return render_template("result.html", title="Lỗi", result=str(e))


@app.route("/decrypt-file", methods=["POST"])
def decrypt_file():
    keynumber = request.form.get("keynumber", "").strip()
    mode      = request.form.get("mode", "ECB")
    file      = request.files.get("file_input")

    if not file or file.filename == "":
        return render_template("result.html", title="Lỗi", result="Chưa chọn file")

    try:
        key = load_key_from_file(KEY_FILE, keynumber)
        input_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(input_path)
        raw = open(input_path, "rb").read()

        t0 = time.perf_counter()
        plain = _cbc_decrypt(raw, key) if mode == "CBC" else triple_des_decrypt_bytes(raw, key)
        elapsed = time.perf_counter() - t0

        base_name = os.path.splitext(file.filename)[0]
        for prefix in (f"encrypted_{mode}_", "encrypted_ECB_", "encrypted_CBC_"):
            if base_name.startswith(prefix):
                base_name = base_name[len(prefix):]
                break
        output_filename = f"decrypted_{mode}_{base_name}.txt"
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)
        with open(output_path, "wb") as f:
            f.write(plain)

        resp = send_file(output_path, as_attachment=True,
                         download_name=output_filename,
                         mimetype="application/octet-stream")
        resp.headers["X-Elapsed"]     = _fmt_time(elapsed)
        resp.headers["X-Input-Size"]  = str(len(raw))
        resp.headers["X-Output-Size"] = str(len(plain))
        return resp
    except Exception as e:
        return render_template("result.html", title="Lỗi", result=str(e))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
