from .crypto import encrypt_text, decrypt_text


def encrypt_file(password: str, input_path: str, output_path: str):
    """
    Reads a file, encrypts its contents, and writes to output file.
    """
    with open(input_path, "r", encoding="utf-8") as f:
        data = f.read()

    encrypted = encrypt_text(password, data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(encrypted)


def decrypt_file(password: str, input_path: str, output_path: str):
    """
    Reads an encrypted file, decrypts it, and writes plaintext to output file.
    """
    with open(input_path, "r", encoding="utf-8") as f:
        data = f.read()

    decrypted = decrypt_text(password, data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(decrypted)
