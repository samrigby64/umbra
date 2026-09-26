"""Conservative identifier validation; a valid address is not an attribution."""
import hashlib

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def bitcoin_base58_valid(value):
    if not 26 <= len(value) <= 35:
        return False
    number = 0
    try:
        for char in value:
            number = number * 58 + ALPHABET.index(char)
    except ValueError:
        return False
    decoded = b"\0" * (len(value)-len(value.lstrip("1"))) + number.to_bytes(
        (number.bit_length()+7)//8, "big")
    return (len(decoded) == 25 and decoded[0] in (0, 5) and
            hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4] == decoded[-4:])
