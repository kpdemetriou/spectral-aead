import pytest
import spectral


class MockedLengthBytes(bytes):
    def __len__(self):
        return 2 ** 32


def test_encryption_invalid_key_type(random_nonce, random_plaintext, random_associated):
    with pytest.raises(TypeError):
        spectral.encrypt_disjoint("", random_nonce, random_plaintext, random_associated)


def test_encryption_invalid_nonce_type(random_key, random_plaintext, random_associated):
    with pytest.raises(TypeError):
        spectral.encrypt_disjoint(random_key, "", random_plaintext, random_associated)


def test_encryption_invalid_plaintext_type(random_key, random_nonce, random_associated):
    with pytest.raises(TypeError):
        spectral.encrypt_disjoint(random_key, random_nonce, "", random_associated)


def test_encryption_invalid_associated_type(random_key, random_nonce, random_plaintext):
    with pytest.raises(TypeError):
        spectral.encrypt_disjoint(random_key, random_nonce, random_plaintext, "")


def test_encryption_invalid_key(random_nonce, random_plaintext, random_associated):
    with pytest.raises(ValueError):
        spectral.encrypt_disjoint(b"\0" * (spectral.KEY_SIZE - 1), random_nonce, random_plaintext, random_associated)

    with pytest.raises(ValueError):
        spectral.encrypt_disjoint(b"\0" * (spectral.KEY_SIZE + 1), random_nonce, random_plaintext, random_associated)


def test_encryption_invalid_nonce(random_key, random_nonce, random_plaintext, random_associated):
    with pytest.raises(ValueError):
        spectral.encrypt_disjoint(random_key, random_nonce[:-1], random_plaintext, random_associated)

    with pytest.raises(ValueError):
        spectral.encrypt_disjoint(random_key, random_nonce + b"\0", random_plaintext, random_associated)


def test_encryption_invalid_plaintext(random_key, random_nonce, random_associated):
    with pytest.raises(ValueError):
        spectral.encrypt_disjoint(random_key, random_nonce, MockedLengthBytes(), random_associated)


def test_encryption_invalid_associated(random_key, random_nonce, random_plaintext):
    with pytest.raises(ValueError):
        spectral.encrypt_disjoint(random_key, random_nonce, random_plaintext, MockedLengthBytes())


def test_decryption_invalid_key_type(random_nonce, random_ciphertext, random_mac, random_associated):
    with pytest.raises(TypeError):
        spectral.decrypt_disjoint("", random_nonce, random_ciphertext, random_mac, random_associated)


def test_decryption_invalid_nonce_type(random_key, random_ciphertext, random_mac, random_associated):
    with pytest.raises(TypeError):
        spectral.decrypt_disjoint(random_key, "", random_ciphertext, random_mac, random_associated)


def test_decryption_invalid_ciphertext_type(random_key, random_nonce, random_mac, random_associated):
    with pytest.raises(TypeError):
        spectral.decrypt_disjoint(random_key, random_nonce, "", random_mac, random_associated)


def test_decryption_invalid_mac_type(random_key, random_nonce, random_ciphertext, random_associated):
    with pytest.raises(TypeError):
        spectral.decrypt_disjoint(random_key, random_nonce, random_ciphertext, "", random_associated)


def test_decryption_invalid_associated_type(random_key, random_nonce, random_ciphertext, random_mac):
    with pytest.raises(TypeError):
        spectral.decrypt_disjoint(random_key, random_nonce, random_ciphertext, random_mac, "")


def test_decryption_invalid_encrypted_type(random_key):
    with pytest.raises(TypeError):
        spectral.decrypt(random_key, "")


def test_decryption_invalid_key(random_key, random_nonce, random_ciphertext, random_mac, random_associated):
    with pytest.raises(ValueError):
        spectral.decrypt_disjoint(random_key[:-1], random_nonce, random_ciphertext, random_mac, random_associated)

    with pytest.raises(ValueError):
        spectral.decrypt_disjoint(random_key + b"\0", random_nonce, random_ciphertext, random_mac, random_associated)


def test_decryption_invalid_nonce(random_key, random_nonce, random_ciphertext, random_mac, random_associated):
    with pytest.raises(ValueError):
        spectral.decrypt_disjoint(random_key, random_nonce[:-1], random_ciphertext, random_mac, random_associated)

    with pytest.raises(ValueError):
        spectral.decrypt_disjoint(random_key, random_nonce + b"\0", random_ciphertext, random_mac, random_associated)


def test_decryption_invalid_mac(random_key, random_nonce, random_ciphertext, random_mac, random_associated):
    with pytest.raises(ValueError):
        spectral.decrypt_disjoint(random_key, random_nonce, random_ciphertext, random_mac[:-1], random_associated)

    with pytest.raises(ValueError):
        spectral.decrypt_disjoint(random_key, random_nonce, random_ciphertext, random_mac + b"\0", random_associated)


def test_decryption_invalid_ciphertext(random_key, random_nonce, random_mac, random_associated):
    with pytest.raises(ValueError):
        spectral.decrypt_disjoint(random_key, random_nonce, MockedLengthBytes(), random_mac, random_associated)


def test_decryption_invalid_associated(random_key, random_nonce, random_ciphertext, random_mac):
    with pytest.raises(ValueError):
        spectral.decrypt_disjoint(random_key, random_nonce, random_ciphertext, random_mac, MockedLengthBytes())


def test_decryption_invalid_encrypted(random_key, random_encrypted):
    with pytest.raises(ValueError):
        spectral.decrypt(random_key, random_encrypted[:-1])
