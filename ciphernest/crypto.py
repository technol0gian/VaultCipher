import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a secure AES key from a password using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_text(password: str, plaintext: str) -> str:
    """
    Encrypts plaintext using AES-256-CBC.
    Returns base64 encoded ciphertext.
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(salt + iv + ciphertext).decode()


def decrypt_text(password: str, encrypted_data: str) -> str:
    """
    Decrypts base64 encoded ciphertext using AES-256-CBC.
    """
    raw_data = base64.b64decode(encrypted_data.encode())

    salt = raw_data[:16]
    iv = raw_data[16:32]
    ciphertext = raw_data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()


def hash_text(text: str) -> str:
    """
    Generates SHA-256 hash of the given text.
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(text.encode())
    return digest.finalize().hex()
