def format_key(key: str, message: str) -> str:

    key = key.lower()
    formatted_key = ""
    key_index = 0

    for char in message:
        if char.isalpha():
            formatted_key += key[key_index % len(key)]
            key_index += 1
        else:
            formatted_key += char

    return formatted_key


def vigenere(message: str, key: str, mode: str) -> str:
    result = ""
    key = format_key(key, message)

    for msg_char, key_char in zip(message, key):
        if not msg_char.isalpha():
            result += msg_char
            continue

        shift = ord(key_char.lower()) - ord('a')

        if mode == "decrypt":
            shift = -shift

        base = ord('A') if msg_char.isupper() else ord('a')
        new_char = chr((ord(msg_char) - base + shift) % 26 + base)
        result += new_char

    return result


def main():
    mode = input("Mode (encrypt/decrypt): ").strip().lower()
    if mode not in ("encrypt", "decrypt"):
        print("Invalid mode.")
        return

    message = input("Message: ")
    key = input("Key: ").strip()

    if not key.isalpha():
        print("Key must contain only letters.")
        return

    result = vigenere(message, key, mode)
    print("\nResult:", result)


if __name__ == "__main__":
    main()
