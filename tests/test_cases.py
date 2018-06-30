import binascii
import spectral


def test_encryption(cases):
    for key, nonce, plaintext, associated, ciphertext, mac in cases:
        key, nonce, plaintext, associated, ciphertext, mac = map(
            binascii.unhexlify, (key, nonce, plaintext, associated, ciphertext, mac)
        )

        computed_ciphertext, computed_mac = spectral.encrypt_disjoint(key, nonce, plaintext, associated)

        assert computed_ciphertext == ciphertext
        assert computed_mac == mac


def test_decryption(cases):
    for key, nonce, plaintext, associated, ciphertext, mac in cases:
        key, nonce, plaintext, associated, ciphertext, mac = map(
            binascii.unhexlify, (key, nonce, plaintext, associated, ciphertext, mac)
        )

        computed_plaintext = spectral.decrypt_disjoint(key, nonce, ciphertext, mac, associated)

        assert computed_plaintext == plaintext
