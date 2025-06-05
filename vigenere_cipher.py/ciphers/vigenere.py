# ciphers/vigenere.py

def repeat_key(key: str, length: int) -> str:
    """
    Repeat the keyword to match the length of the text.
    Example: repeat_key("KEY", 6) → "KEYKEY"
    """
    key = key.upper()
    return (key * (length // len(key) + 1))[:length]

def vigenere_encrypt(text: str, keyword: str) -> str:
    """
    Encrypt the input text using the Vigenère cipher with the given keyword.
    Only alphabetic characters are shifted; other characters are preserved.
    """
    text = text.upper()
    key = keyword.upper()
    result = []
    key_idx = 0

    for t_char in text:
        if t_char.isalpha():
            k_char = key[key_idx % len(key)]
            shift = ord(k_char) - ord('A')
            encrypted_char = chr((ord(t_char) - ord('A') + shift) % 26 + ord('A'))
            result.append(encrypted_char)
            key_idx += 1
        else:
            result.append(t_char)

    return ''.join(result)

def vigenere_decrypt(text: str, keyword: str) -> str:
    """
    Decrypt the input text using the Vigenère cipher with the given keyword.
    Only alphabetic characters are shifted; other characters are preserved.
    """
    text = text.upper()
    key = keyword.upper()
    result = []
    key_idx = 0

    for t_char in text:
        if t_char.isalpha():
            k_char = key[key_idx % len(key)]
            shift = ord(k_char) - ord('A')
            decrypted_char = chr((ord(t_char) - ord('A') - shift + 26) % 26 + ord('A'))
            result.append(decrypted_char)
            key_idx += 1
        else:
            result.append(t_char)

    return ''.join(result)
