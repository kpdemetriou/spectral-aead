import os
import json
import pytest
import spectral


@pytest.fixture
def random_key():
    return os.urandom(spectral.KEY_SIZE)


@pytest.fixture()
def random_nonce():
    return os.urandom(spectral.NONCE_SIZE)


@pytest.fixture
def random_plaintext():
    return os.urandom(16)


@pytest.fixture
def random_ciphertext():
    return os.urandom(16)


@pytest.fixture
def random_mac():
    return os.urandom(spectral.HASH_DIGEST_SIZE)


@pytest.fixture
def random_associated():
    return os.urandom(16)


@pytest.fixture
def random_encrypted():
    return os.urandom(spectral.NONCE_SIZE + spectral.HASH_DIGEST_SIZE)


@pytest.fixture
def cases():
    cases_file_path = os.path.join(os.path.dirname(__file__), "cases.json")
    return json.load(open(cases_file_path, "r"))
