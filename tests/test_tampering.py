import pytest
import random
import spectral


@pytest.mark.parametrize("execution", range(1000))
def test_joint(execution, random_key, random_plaintext, random_associated):
    encrypted = spectral.encrypt(random_key, random_plaintext, random_associated)

    encrypted = bytearray(encrypted)
    flip_index = random.randint(0, len(encrypted) - 1)
    encrypted[flip_index] = 255 - encrypted[flip_index]
    encrypted = bytes(encrypted)

    with pytest.raises(RuntimeError):
        spectral.decrypt(random_key, encrypted, random_associated)


@pytest.mark.parametrize("execution", range(1000))
def test_disjoint_ciphertext(execution, random_key, random_nonce, random_plaintext, random_associated):
    ciphertext, mac = spectral.encrypt_disjoint(random_key, random_nonce, random_plaintext, random_associated)

    ciphertext = bytearray(ciphertext)
    flip_index = random.randint(0, len(ciphertext) - 1)
    ciphertext[flip_index] = 255 - ciphertext[flip_index]
    ciphertext = bytes(ciphertext)

    with pytest.raises(RuntimeError):
        spectral.decrypt_disjoint(random_key, random_nonce, ciphertext, mac, random_associated)


@pytest.mark.parametrize("execution", range(1000))
def test_disjoint_mac(execution, random_key, random_nonce, random_plaintext, random_associated):
    ciphertext, mac = spectral.encrypt_disjoint(random_key, random_nonce, random_plaintext, random_associated)

    mac = bytearray(mac)
    flip_index = random.randint(0, len(mac) - 1)
    mac[flip_index] = 255 - mac[flip_index]
    mac = bytes(mac)

    with pytest.raises(RuntimeError):
        spectral.decrypt_disjoint(random_key, random_nonce, ciphertext, mac, random_associated)
