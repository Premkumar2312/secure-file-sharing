from cryptography.fernet import Fernet, InvalidToken


def generate_key() -> bytes:
    """Generate a new URL-safe Fernet key."""
    return Fernet.generate_key()


def encrypt_file(contents: bytes, key: bytes) -> bytes:
    """Return authenticated encrypted bytes."""
    return Fernet(key).encrypt(contents)


def decrypt_file(contents: bytes, key: bytes) -> bytes:
    """Decrypt bytes, raising InvalidToken when the key or data is invalid."""
    return Fernet(key).decrypt(contents)


__all__ = ["generate_key", "encrypt_file", "decrypt_file", "InvalidToken"]
