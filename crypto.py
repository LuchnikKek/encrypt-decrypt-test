from __future__ import annotations

from dataclasses import dataclass

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey.RSA import RsaKey
from Cryptodome.Random import get_random_bytes


@dataclass
class EncryptedMessage:
    """Some important message."""

    nonce: bytes
    digest: bytes
    message: bytes


def generate_key_pair() -> tuple[RsaKey, RsaKey]:
    """Generate two keys: private and public.

    Returns:
        A tuple of two rsa keys.
    """
    key = RSA.generate(2048)

    return key, key.publickey()


def encrypt_session_key(session_key: bytes, public_key: RsaKey) -> int:
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    return enc_session_key


def decrypt_session_key(encrypted_session_key: bytes, private_key: RsaKey) -> bytes:
    """Decrypt encrypted session key by private RSA key.

    Args:
        encrypted_session_key: An encrypted session key.
        private_key: A private RSA key.

    Returns:
        bytes: A decrypted session key.
    """
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    return session_key


def encrypt(data: str, session_key: bytes) -> EncryptedMessage:
    """Encrypt and sign the message using the symmetric block cipher algorithm (AES).

    Encryption modes are used for such algorithms.
    In this case, EAX mode is used, which allows you to simultaneously encrypt data blocks and authenticate them.

    Args:
        data: A data to encrypt.
        session_key: A session key.

    Returns:
        EncryptedMessage: Encrypted message.
    """
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    cipher_text, digest = cipher_aes.encrypt_and_digest(data.encode())

    return EncryptedMessage(nonce=cipher_aes.nonce, digest=digest, message=cipher_text)


def decrypt(encrypted: EncryptedMessage, session_key: bytes) -> str:
    """Decrypt a message, using a session key.

    Args:
    encrypted: An encrypted message.
    session_key: A session key.

    Returns:
    A decrypted message string.
    """
    cipher_aes = AES.new(session_key, AES.MODE_EAX, encrypted.nonce)
    data = cipher_aes.decrypt_and_verify(encrypted.message, encrypted.digest)

    return data.decode()


if __name__ == "__main__":
    raw = "message to encrypt"
    session_key = get_random_bytes(16)
    priv_key, pub_key = generate_key_pair()

    # Server side
    encrypted_session_key = encrypt_session_key(session_key, pub_key)
    encrypted_data = encrypt(raw, session_key)
    print("Зашифрованный сессионный ключ:", encrypted_session_key)  # noqa: T201
    print("Зашифрованное сообщение:", encrypted_data.message)  # noqa: T201

    # Cliend side
    decrypted_session_key = decrypt_session_key(encrypted_session_key, priv_key)
    print("Расшифрованное сообщение:", decrypt(encrypted_data, decrypted_session_key))  # noqa: T201
