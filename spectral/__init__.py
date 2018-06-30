import os
from ._spectral import ffi as __ffi, lib as __lib

KEY_SIZE = 16
NONCE_SIZE = 16

CIPHER_BLOCK_SIZE = 16
CIPHER_ROUNDS = 32

HASH_BLOCK_SIZE = 64
HASH_DIGEST_SIZE = 32


def __validate_encryption_in(key, nonce, plaintext, associated):
    if not isinstance(key, bytes):
        raise TypeError("'key' must be of type 'bytes'")

    if not isinstance(nonce, bytes):
        raise TypeError("'nonce' must be of type 'bytes'")

    if not isinstance(plaintext, bytes):
        raise TypeError("'plaintext' must be of type 'bytes'")

    if not isinstance(associated, bytes):
        raise TypeError("'associated' must be of type 'bytes'")

    if len(key) != KEY_SIZE:
        raise ValueError("'key' must be of length '{}' octets".format(KEY_SIZE))

    if len(nonce) != NONCE_SIZE:
        raise ValueError("'nonce' must be of length '{}' octets".format(NONCE_SIZE))

    if len(plaintext) > 2 ** 32 - 1:
        raise ValueError("'plaintext' must be shorter than '2^32 - 1' octets")

    if len(associated) > 2 ** 31 - 1:
        raise ValueError("'associated' must be shorter than '2^32 - 1' octets")

    return key, nonce, plaintext, associated


def __validate_decryption_in(key, nonce, ciphertext, mac, associated):
    if not isinstance(key, bytes):
        raise TypeError("'key' must be of type 'bytes'")

    if not isinstance(nonce, bytes):
        raise TypeError("'nonce' must be of type 'bytes'")

    if not isinstance(ciphertext, bytes):
        raise TypeError("'plaintext' must be of type 'bytes'")

    if not isinstance(mac, bytes):
        raise TypeError("'mac' must be of type 'bytes'")

    if not isinstance(associated, bytes):
        raise TypeError("'associated' must be of type 'bytes'")

    if len(key) != KEY_SIZE:
        raise ValueError("'key' must be of length '{}' octets".format(KEY_SIZE))

    if len(nonce) != NONCE_SIZE:
        raise ValueError("'nonce' must be of length '{}' octets".format(NONCE_SIZE))

    if len(mac) != HASH_DIGEST_SIZE:
        raise ValueError("'mac' must be of length '{}' octets".format(HASH_DIGEST_SIZE))

    if len(ciphertext) > 2 ** 32 - 1:
        raise ValueError("'ciphertext' must be shorter than '2^31 - 1' octets")

    if len(associated) > 2 ** 31 - 1:
        raise ValueError("'associated' must be shorter than '2^31 - 1' octets")

    return key, nonce, ciphertext, mac, associated


def __aead_encrypt(key, nonce, plaintext, associated):
    length_plaintext = len(plaintext)
    buffer_ciphertext = __ffi.new("CRYPTO_OCTET[{}]".format(length_plaintext))
    buffer_mac = __ffi.new("CRYPTO_OCTET[{}]".format(HASH_DIGEST_SIZE))

    code = __lib.aead_encrypt(
        key, nonce, plaintext, length_plaintext, associated, len(associated), buffer_ciphertext, buffer_mac
    )

    return (
        code,
        bytes(__ffi.buffer(buffer_ciphertext, length_plaintext)),
        bytes(__ffi.buffer(buffer_mac, HASH_DIGEST_SIZE)),
    )


def __aead_decrypt(key, nonce, ciphertext, mac, associated):
    length_ciphertext = len(ciphertext)
    buffer_plaintext = __ffi.new("CRYPTO_OCTET[{}]".format(length_ciphertext))

    code = __lib.aead_decrypt(
        key, nonce, mac, ciphertext, length_ciphertext, associated, len(associated), buffer_plaintext
    )

    return code, bytes(__ffi.buffer(buffer_plaintext, length_ciphertext))


def create_nonce():
    return os.urandom(NONCE_SIZE)


def encrypt_disjoint(key, nonce, plaintext, associated=b""):
    key, nonce, plaintext, associated = __validate_encryption_in(key, nonce, plaintext, associated)
    code, ciphertext, mac = __aead_encrypt(key, nonce, plaintext, associated)

    if code != 1:
        raise RuntimeError("Encryption failed")

    return ciphertext, mac


def decrypt_disjoint(key, nonce, ciphertext, mac, associated=b""):
    key, nonce, ciphertext, mac, associated = __validate_decryption_in(key, nonce, ciphertext, mac, associated)
    code, plaintext = __aead_decrypt(key, nonce, ciphertext, mac, associated)

    if code != 1:
        raise RuntimeError("Decryption failed or data tampering has occurred")

    return plaintext


def encrypt(key, plaintext, associated=b""):
    nonce = create_nonce()

    key, nonce, plaintext, associated = __validate_encryption_in(key, nonce, plaintext, associated)
    code, ciphertext, mac = __aead_encrypt(key, nonce, plaintext, associated)

    if code != 1:
        raise RuntimeError("Encryption failed")

    return nonce + ciphertext + mac


def decrypt(key, encrypted, associated=b""):
    if not isinstance(encrypted, bytes):
        raise TypeError("'encrypted' must be of type 'bytes'")

    if len(encrypted) < (NONCE_SIZE + HASH_DIGEST_SIZE):
        raise ValueError("'encrypted' must be at least of length '{}' octets".format(HASH_DIGEST_SIZE))

    nonce, ciphertext, mac = (
        encrypted[:NONCE_SIZE],
        encrypted[NONCE_SIZE:-HASH_DIGEST_SIZE],
        encrypted[-HASH_DIGEST_SIZE:],
    )

    key, nonce, ciphertext, mac, associated = __validate_decryption_in(key, nonce, ciphertext, mac, associated)
    code, plaintext = __aead_decrypt(key, nonce, ciphertext, mac, associated)

    if code != 1:
        raise RuntimeError("Decryption failed or data tampering has occurred")

    return plaintext
