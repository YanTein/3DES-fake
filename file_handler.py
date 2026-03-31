# file_handler.py

def read_text_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_text_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)