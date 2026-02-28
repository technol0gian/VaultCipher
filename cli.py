import argparse
from ciphernest.crypto import encrypt_text, decrypt_text, hash_text
from ciphernest.file_ops import encrypt_file, decrypt_file


def main():
    parser = argparse.ArgumentParser(description="CipherNest Crypto Toolkit")

    parser.add_argument("--mode", required=True,
                        choices=["encrypt", "decrypt", "hash", "encrypt-file", "decrypt-file"],
                        help="Operation mode")

    parser.add_argument("--password", help="Password for encryption/decryption")
    parser.add_argument("--text", help="Text to encrypt/decrypt/hash")
    parser.add_argument("--input", help="Input file path")
    parser.add_argument("--output", help="Output file path")

    args = parser.parse_args()

    if args.mode == "encrypt":
        print(encrypt_text(args.password, args.text))

    elif args.mode == "decrypt":
        print(decrypt_text(args.password, args.text))

    elif args.mode == "hash":
        print(hash_text(args.text))

    elif args.mode == "encrypt-file":
        encrypt_file(args.password, args.input, args.output)
        print("File encrypted successfully.")

    elif args.mode == "decrypt-file":
        decrypt_file(args.password, args.input, args.output)
        print("File decrypted successfully.")


if __name__ == "__main__":
    main()
