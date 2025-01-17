import re
import base64
import string

def is_base64(s):
    """Check if a string is Base64 encoded."""
    try:
        if base64.b64encode(base64.b64decode(s)).decode() == s:
            return True
    except Exception:
        pass
    return False

def is_rot13(s):
    """Check if a string is ROT13 by decoding and checking for readable text."""
    rot13 = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    )
    decoded = s.translate(rot13)
    if all(c in string.printable for c in decoded):  # Check if the result is readable
        return True
    return False

def identify_hash(hash_string):
    hash_patterns = {
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA-1": r"^[a-fA-F0-9]{40}$",
        "SHA-224": r"^[a-fA-F0-9]{56}$",
        "SHA-256": r"^[a-fA-F0-9]{64}$",
        "SHA-384": r"^[a-fA-F0-9]{96}$",
        "SHA-512": r"^[a-fA-F0-9]{128}$",
        "NTLM": r"^[a-fA-F0-9]{32}$",
        "LM": r"^[a-fA-F0-9]{32}$",
        "MySQL": r"^[a-fA-F0-9]{16}$",
        "MySQL5": r"^[a-fA-F0-9]{40}$",
        "Oracle 11g": r"^S:[A-Z0-9]{60}$",
        "CRC32": r"^[A-F0-9]{8}$",
        "Blowfish/Eggdrop": r"^\+[a-zA-Z0-9/.]{12}$",
        "DES(Unix)": r"^.{2}[a-zA-Z0-9/.]{11}$",
        "bcrypt": r"^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}$",
        "SHA-1(Base64)": r"^[a-zA-Z0-9+/]{27}=$",
        "SHA-256(Base64)": r"^[a-zA-Z0-9+/]{43}=$",
        "SHA-512(Base64)": r"^[a-zA-Z0-9+/]{86}=$",
        "WPA/WPA2": r"^[a-fA-F0-9]{64}$",
        "Hexadecimal": r"^[a-fA-F0-9]+$",  # Generic hex pattern
    }

    matched_hashes = []

    # Check patterns
    for hash_name, pattern in hash_patterns.items():
        if re.match(pattern, hash_string):
            matched_hashes.append(hash_name)

    # Check Base64 (more specific than regex-based checks)
    if is_base64(hash_string):
        matched_hashes.append("Base64")

    # Check ROT13
    if is_rot13(hash_string):
        matched_hashes.append("ROT13")

    return matched_hashes if matched_hashes else ["Unknown type"]

# Example usage
if __name__ == "__main__":
    hash_input = input("Enter a hash or string: ").strip()
    hash_results = identify_hash(hash_input)

    print("Identified Types:")
    for hash_type in hash_results:
        print(f"- {hash_type}")
