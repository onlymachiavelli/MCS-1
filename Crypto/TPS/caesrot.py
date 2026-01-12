def rotate_char(c: str, k: int) -> str:
    k = k % 26

    if 'A' <= c <= 'Z':
        base = ord('A')
        return chr((ord(c) - base + k) % 26 + base)

    if 'a' <= c <= 'z':
        base = ord('a')
        return chr((ord(c) - base + k) % 26 + base)

    return c


def encrypt(text: str, k: int) -> str:
    return ''.join(rotate_char(c, k) for c in text)


def decrypt(text: str, k: int) -> str:
    return ''.join(rotate_char(c, -k) for c in text)


def main():
    mode = input("Mode (encrypt/decrypt): ").strip().lower()
    text = input("Message: ")
    k = int(input("Key (integer): "))

    if mode == "encrypt":
        print("Encrypted:", encrypt(text, k))
    elif mode == "decrypt":
        print("Decrypted:", decrypt(text, k))
    else:
        print("Invalid mode.")


if __name__ == "__main__":
    main()
