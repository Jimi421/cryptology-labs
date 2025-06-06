# ciphers/vigenere.py

def repeat_key(key: str, length: int) -> str:
    """
    Repeat the keyword to match the length of the text.
    Example: repeat_key("KEY", 6) → "KEYKEY"
    """
    key = key.upper()
    return (key * (length // len(key) + 1))[:length]

from typing import Dict, Iterable, Optional


def _map_encrypt(ch: str, mapping: Optional[Dict[str, Iterable[str]]]) -> str:
    """Map a ciphertext character using the homophonic mapping (first option)."""
    if not mapping:
        return ch
    opts = mapping.get(ch)
    if not opts:
        return ch
    if isinstance(opts, str):
        return opts[0]
    try:
        return next(iter(opts))
    except StopIteration:
        return ch


def _map_decrypt(ch: str, mapping: Optional[Dict[str, Iterable[str]]]) -> str:
    """Reverse-map a ciphertext character back to its canonical letter."""
    if not mapping:
        return ch
    for plain, opts in mapping.items():
        if isinstance(opts, str):
            if ch in opts:
                return plain
        else:
            if ch in opts:
                return plain
    return ch


def vigenere_encrypt(text: str, keyword: str, homophonic_map: Optional[Dict[str, Iterable[str]]] = None) -> str:
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
            encrypted_char = _map_encrypt(encrypted_char, homophonic_map)
            result.append(encrypted_char)
            key_idx += 1
        else:
            result.append(t_char)

    return ''.join(result)

def vigenere_decrypt(text: str, keyword: str, homophonic_map: Optional[Dict[str, Iterable[str]]] = None) -> str:
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
            t_mapped = _map_decrypt(t_char, homophonic_map)
            k_char = key[key_idx % len(key)]
            shift = ord(k_char) - ord('A')
            decrypted_char = chr((ord(t_mapped) - ord('A') - shift + 26) % 26 + ord('A'))
            result.append(decrypted_char)
            key_idx += 1
        else:
            result.append(t_char)

    return ''.join(result)


def vigenere_autokey_encrypt(
    text: str,
    keyword: str,
    homophonic_map: Optional[Dict[str, Iterable[str]]] = None,
) -> str:
    """Encrypt text using the autokey variant (keyword + plaintext)."""
    text = text.upper()
    key_queue = list(keyword.upper())
    result = []
    for t_char in text:
        if t_char.isalpha():
            k_char = key_queue.pop(0)
            shift = ord(k_char) - ord('A')
            enc = chr((ord(t_char) - ord('A') + shift) % 26 + ord('A'))
            enc = _map_encrypt(enc, homophonic_map)
            result.append(enc)
            key_queue.append(t_char)
        else:
            result.append(t_char)
    return ''.join(result)


def vigenere_autokey_decrypt(
    text: str,
    keyword: str,
    homophonic_map: Optional[Dict[str, Iterable[str]]] = None,
) -> str:
    """Decrypt an autokey Vigenère ciphertext."""
    text = text.upper()
    key_queue = list(keyword.upper())
    result = []
    for t_char in text:
        if t_char.isalpha():
            mapped = _map_decrypt(t_char, homophonic_map)
            k_char = key_queue.pop(0)
            shift = ord(k_char) - ord('A')
            plain = chr((ord(mapped) - ord('A') - shift + 26) % 26 + ord('A'))
            result.append(plain)
            key_queue.append(plain)
        else:
            result.append(t_char)
    return ''.join(result)
