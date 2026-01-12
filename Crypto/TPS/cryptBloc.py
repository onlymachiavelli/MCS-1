import os

BLOCK_SIZE = 16


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty data.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding.")
    return data[:-pad_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def normalize_key(key_str: str, size: int = BLOCK_SIZE) -> bytes:
    key = key_str.encode("utf-8")
    if len(key) >= size:
        return key[:size]
    return key + bytes([0] * (size - len(key)))


def encrypt_block(block: bytes, key: bytes) -> bytes:
    return xor_bytes(block, key)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    return xor_bytes(block, key)


def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    plaintext = pkcs7_pad(plaintext, BLOCK_SIZE)
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        out += encrypt_block(block, key)
    return bytes(out)


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        out += decrypt_block(block, key)
    return pkcs7_unpad(bytes(out))


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    plaintext = pkcs7_pad(plaintext, BLOCK_SIZE)
    out = bytearray()
    prev = iv
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        x = xor_bytes(block, prev)
        c = encrypt_block(x, key)
        out += c
        prev = c
    return bytes(out)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        x = decrypt_block(block, key)
        p = xor_bytes(x, prev)
        out += p
        prev = block
    return pkcs7_unpad(bytes(out))


def main():
    mode = input("Mode (ecb/cbc): ").strip().lower()
    msg = input("Message to encrypt: ").encode("utf-8")
    key_str = input("Key: ")

    key = normalize_key(key_str)

    if mode == "ecb":
        ciphertext = encrypt_ecb(msg, key)
        print("Ciphertext (hex, ECB):", ciphertext.hex())
    elif mode == "cbc":
        iv = os.urandom(16)
        ciphertext = encrypt_cbc(msg, key, iv)
        print("IV (hex):", iv.hex())
        print("Ciphertext (hex, CBC):", ciphertext.hex())
    else:
        print("Unknown mode.")



if __name__ == "__main__":
    main()
