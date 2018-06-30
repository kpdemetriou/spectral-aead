#ifndef SPECTRAL_H
#define SPECTRAL_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include <stdint.h>

/****************************** MACROS ******************************/
#define KEY_SIZE 16
#define NONCE_SIZE 16

#define CIPHER_BLOCK_SIZE 16
#define CIPHER_ROUNDS 32

#define HASH_BLOCK_SIZE 64
#define HASH_DIGEST_SIZE 32

/**************************** DATA TYPES ****************************/
typedef uint8_t CRYPTO_OCTET;
typedef uint32_t CRYPTO_WORD;
typedef uint64_t CRYPTO_QWORD;

typedef struct {
    CRYPTO_OCTET data[HASH_BLOCK_SIZE];
    CRYPTO_WORD datalen;
    CRYPTO_QWORD bitlen;
    CRYPTO_WORD state[HASH_DIGEST_SIZE / sizeof(CRYPTO_WORD)];
} HASH_CTX;

typedef struct {
    CRYPTO_OCTET key[HASH_BLOCK_SIZE];
    HASH_CTX hc1;
    HASH_CTX hc2;
} HMAC_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
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

#endif   // SPECTRAL_H
