import os
from cffi import FFI

CFFI_CDEF = """
    #define KEY_SIZE 16
    #define NONCE_SIZE 16
    
    #define CIPHER_BLOCK_SIZE 16
    #define CIPHER_ROUNDS 32
    
    #define HASH_BLOCK_SIZE 64
    #define HASH_DIGEST_SIZE 32
    
    typedef uint8_t CRYPTO_OCTET;
    typedef uint32_t CRYPTO_WORD;
    typedef unsigned long long CRYPTO_QWORD;
    
    int aead_encrypt(
        const CRYPTO_OCTET key[KEY_SIZE], const CRYPTO_OCTET nonce[NONCE_SIZE],
        const CRYPTO_OCTET pt[], const size_t pt_len,
        const CRYPTO_OCTET ad[], const size_t ad_len,
        CRYPTO_OCTET ct[], CRYPTO_OCTET mac[HASH_DIGEST_SIZE]
    );
    
    int aead_decrypt(
        const CRYPTO_OCTET key[KEY_SIZE], const CRYPTO_OCTET nonce[NONCE_SIZE],
        const CRYPTO_OCTET mac[HASH_DIGEST_SIZE], const CRYPTO_OCTET ct[], const size_t ct_len,
        const CRYPTO_OCTET ad[], const size_t ad_len, CRYPTO_OCTET pt[]
    );
"""

source_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sources")

spectral_ffi = FFI()
spectral_ffi.cdef(CFFI_CDEF)

with open(os.path.join(source_directory, "spectral.c")) as spectral_source_file:
    spectral_ffi.set_source("spectral._spectral", spectral_source_file.read(), include_dirs=[source_directory])

if __name__ == "__main__":
    spectral_ffi.compile(verbose=True)
