import spectral


def test_encryption_disjoint(random_key, random_nonce, random_plaintext, random_associated):
    spectral.encrypt_disjoint(random_key, random_nonce, random_plaintext, random_associated)


def test_decryption_disjoint(random_key, random_nonce, random_plaintext, random_associated):
    ciphertext, mac = spectral.encrypt_disjoint(random_key, random_nonce, random_plaintext, random_associated)
    assert random_plaintext == spectral.decrypt_disjoint(random_key, random_nonce, ciphertext, mac, random_associated)


def test_encryption(random_key, random_plaintext, random_associated):
    spectral.encrypt(random_key, random_plaintext, random_associated)


def test_decryption(random_key, random_plaintext, random_associated):
    encrypted = spectral.encrypt(random_key, random_plaintext, random_associated)
    assert random_plaintext == spectral.decrypt(random_key, encrypted, random_associated)
