#!/usr/bin/env python3
"""
Caesar Cipher Encoder

Usage:
  python3 caesar_encode.py --shift N "Your plaintext here"

This script applies a positive Caesar shift to encode input text.
"""
import argparse
import sys


def caesar_shift(text: str, shift: int) -> str:
    """Shift each alphabetic character in text by `shift` positions (A–Z, a–z)."""
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)


def main():
    parser = argparse.ArgumentParser(description="Caesar Cipher Encoder")
    parser.add_argument(
        '--shift',
        type=int,
        required=True,
        help='Positive shift amount to apply'
    )
    parser.add_argument(
        'plaintext',
        help='Plaintext string to encode'
    )
    args = parser.parse_args()

    encoded = caesar_shift(args.plaintext, args.shift)
    print(encoded)


if __name__ == '__main__':
    main()
