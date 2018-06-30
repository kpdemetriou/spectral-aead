/****************************** HEADERS *****************************/
#include <stdlib.h>
#include <stdint.h>
#include <memory.h>
#include "spectral.h"

/****************************** MACROS ******************************/
#define ROR(x, r, b) ((x >> r) | (x << (b - r)))
#define ROL(x, r, b) ((x << r) | (x >> (b - r)))

#define CIPHER_R(x, y, k) (x = ROR(x, 8, 64), x += y, x ^= k, y = ROL(y, 3, 64), y ^= x)

#define HASH_CH(x, y, z) ((x & y) ^ (~x & z))
#define HASH_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define HASH_EP(x, i, j, k) (ROR(x, i, 32) ^ ROR(x, j, 32) ^ ROR(x, k, 32))
#define HASH_SIG(x, i, j, k) (ROR(x, i, 32) ^ ROR(x, j, 32) ^ (x >> k))
#define HASH_EP0(x) (HASH_EP(x, 2, 13, 22))
#define HASH_EP1(x) (HASH_EP(x, 6, 11, 25))
#define HASH_SIG0(x) (HASH_SIG(x, 7, 18, 3))
#define HASH_SIG1(x) (HASH_SIG(x, 17, 19, 10))

/***************************** CONSTANTS ****************************/
static const CRYPTO_WORD hash_initial[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const CRYPTO_WORD hash_magic[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/***************************** FUNCTIONS ****************************/
int util_const_compare(
    volatile const CRYPTO_OCTET* buf1, volatile const CRYPTO_OCTET* buf2, size_t buf_len
) {
    volatile char c = 0;

    for (size_t i = 0; i < buf_len; ++i)
        c |= buf1[i] ^ buf2[i];

    return (c == 0);
}

void util_buf_xor(
    const CRYPTO_OCTET in[], CRYPTO_OCTET out[], size_t len
) {
    for (size_t idx = 0; idx < len; idx++)
        out[idx] ^= in[idx];
}

void hash_transform(
    HASH_CTX *ctx, const CRYPTO_OCTET data[]
) {
    CRYPTO_WORD a, b, c, d, e, f, g, h, j, t1, t2, m[64];
    size_t  i;

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);

    for (; i < 64; ++i)
        m[i] = HASH_SIG1(m[i - 2]) + m[i - 7] + HASH_SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + HASH_EP1(e) + HASH_CH(e, f, g) + hash_magic[i] + m[i];
        t2 = HASH_EP0(a) + HASH_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void hash_init(
    HASH_CTX *ctx
) {
    ctx->datalen = 0;
    ctx->bitlen = 0;

    for (size_t i = 0; i < 8; ++i)
        ctx->state[i] = hash_initial[i];
}

void hash_update(
    HASH_CTX *ctx, const CRYPTO_OCTET data[], size_t data_len
) {
    for (size_t i = 0; i < data_len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;

        if (ctx->datalen == 64) {
            hash_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void hash_final(
    HASH_CTX *ctx, CRYPTO_OCTET hash[]
) {
    CRYPTO_WORD i;
    i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        hash_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    hash_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

void hmac_init(
    HMAC_CTX *ctx, const CRYPTO_OCTET key[KEY_SIZE]
) {
    HASH_CTX hc1, hc2;

    hash_init(&hc1);
    hash_init(&hc2);

    if (KEY_SIZE > HASH_BLOCK_SIZE) {
        HASH_CTX hmk_ctx;
        hash_init(&hmk_ctx);
        hash_update(&hmk_ctx, key, KEY_SIZE);
        hash_final(&hmk_ctx, ctx->key);
    }

    if (KEY_SIZE < HASH_BLOCK_SIZE) {
        for (size_t i = 0; i < HASH_BLOCK_SIZE; ctx->key[i++] = 0);
        memcpy(ctx->key, key, KEY_SIZE * sizeof(CRYPTO_OCTET));
    }

    CRYPTO_OCTET o_key_pad[HASH_BLOCK_SIZE];
    CRYPTO_OCTET i_key_pad[HASH_BLOCK_SIZE];

    for (size_t i = 0; i < HASH_BLOCK_SIZE; ++i) {
        o_key_pad[i] = 0x5c ^ ctx->key[i];
        i_key_pad[i] = 0x36 ^ ctx->key[i];
    }

    hash_update(&hc1, i_key_pad, HASH_BLOCK_SIZE);
    hash_update(&hc2, o_key_pad, HASH_BLOCK_SIZE);

    ctx->hc1 = hc1;
    ctx->hc2 = hc2;
}

void hmac_update(
    HMAC_CTX *ctx, const CRYPTO_OCTET data[], size_t data_len
) {
    hash_update(&ctx->hc1, data, data_len);
}

void hmac_final(
    HMAC_CTX *ctx, CRYPTO_OCTET mac[HASH_DIGEST_SIZE]
) {
    hash_final(&ctx->hc1, mac);
    hash_update(&ctx->hc2, mac, HASH_DIGEST_SIZE);
    hash_final(&ctx->hc2, mac);
}

void cipher_block(
    const CRYPTO_QWORD key[KEY_SIZE/sizeof(CRYPTO_QWORD)],
    const CRYPTO_QWORD pt[CIPHER_BLOCK_SIZE / sizeof(CRYPTO_QWORD)],
    CRYPTO_QWORD ct[CIPHER_BLOCK_SIZE / sizeof(CRYPTO_QWORD)]
) {
    CRYPTO_QWORD y = pt[0], x = pt[1], b = key[0], a = key[1];

    CIPHER_R(x, y, b);
    for (int i = 0; i < CIPHER_ROUNDS - 1; ++i) {
        CIPHER_R(a, b, i);
        CIPHER_R(x, y, b);
    }

    ct[0] = y;
    ct[1] = x;
}

void cipher_nonce_inc(
    CRYPTO_OCTET nonce[], const size_t counter_size
) {
    for (size_t idx = CIPHER_BLOCK_SIZE - 1; idx >= CIPHER_BLOCK_SIZE - counter_size; idx--) {
        nonce[idx]++;

        if (nonce[idx] != 0 || idx == CIPHER_BLOCK_SIZE - counter_size)
            break;
    }
}

void cipher_ctr(
    const CRYPTO_OCTET key[KEY_SIZE], const CRYPTO_OCTET nonce[NONCE_SIZE],
    const CRYPTO_OCTET pt[], const size_t pt_len, CRYPTO_OCTET ct[]
) {
    CRYPTO_QWORD block_key[KEY_SIZE / sizeof(CRYPTO_QWORD)];
    CRYPTO_QWORD block_nonce[NONCE_SIZE / sizeof(CRYPTO_QWORD)];

    for(size_t i = 0; i < KEY_SIZE / sizeof(CRYPTO_QWORD); ++i)
        memcpy(block_key + i, key + i * sizeof(CRYPTO_QWORD) / sizeof(CRYPTO_OCTET), sizeof(CRYPTO_QWORD));

    for (size_t i = 0; i < NONCE_SIZE / sizeof(CRYPTO_QWORD); ++i)
        memcpy(block_nonce + i, key + i * sizeof(CRYPTO_QWORD) / sizeof(CRYPTO_OCTET), sizeof(CRYPTO_QWORD));

    size_t idx = 0, last_block_length;
    CRYPTO_OCTET nonce_buf[NONCE_SIZE], out_buf[CIPHER_BLOCK_SIZE];

    if (pt != ct)
        memcpy(ct, pt, pt_len);

    memcpy(nonce_buf, nonce, NONCE_SIZE);
    last_block_length = pt_len - CIPHER_BLOCK_SIZE;

    if (pt_len > CIPHER_BLOCK_SIZE) {
        for (idx = 0; idx < last_block_length; idx += CIPHER_BLOCK_SIZE) {
            cipher_block(block_key, (CRYPTO_QWORD*) nonce_buf, (CRYPTO_QWORD*) out_buf);
            util_buf_xor(out_buf, &ct[idx], CIPHER_BLOCK_SIZE);
            cipher_nonce_inc(nonce_buf, CIPHER_BLOCK_SIZE);
        }
    }

    cipher_block(block_key, (CRYPTO_QWORD*) nonce_buf, (CRYPTO_QWORD*) out_buf);
    util_buf_xor(out_buf, &ct[idx], pt_len - idx);
}

int aead_encrypt(
    const CRYPTO_OCTET key[KEY_SIZE], const CRYPTO_OCTET nonce[NONCE_SIZE],
    const CRYPTO_OCTET pt[], const size_t pt_len,
    const CRYPTO_OCTET ad[], const size_t ad_len,
    CRYPTO_OCTET ct[], CRYPTO_OCTET mac[HASH_DIGEST_SIZE]
) {
    HMAC_CTX hmc = {0};
    hmac_init(&hmc, key);

    CRYPTO_OCTET ct_len_repr[sizeof(CRYPTO_WORD)];
    for (size_t i = 0; i < sizeof(CRYPTO_WORD); ++i)
        ct_len_repr[i] = pt_len >> (8 * i);

    CRYPTO_OCTET ad_len_repr[sizeof(CRYPTO_WORD)];
    for (size_t i = 0; i < sizeof(CRYPTO_WORD); ++i)
        ad_len_repr[i] = ad_len >> (8 * i);

    cipher_ctr(key, nonce, pt, pt_len, ct);
    hmac_update(&hmc, nonce, NONCE_SIZE);
    hmac_update(&hmc, ct_len_repr, sizeof(CRYPTO_WORD));
    hmac_update(&hmc, ct, pt_len);
    hmac_update(&hmc, ad_len_repr, sizeof(CRYPTO_WORD));
    hmac_update(&hmc, ad, ad_len);
    hmac_final(&hmc, mac);

    return 1;
}

int aead_decrypt(
    const CRYPTO_OCTET key[KEY_SIZE], const CRYPTO_OCTET nonce[NONCE_SIZE],
    const CRYPTO_OCTET mac[HASH_DIGEST_SIZE], const CRYPTO_OCTET ct[], const size_t ct_len,
    const CRYPTO_OCTET ad[], const size_t ad_len, CRYPTO_OCTET pt[]
) {
    HMAC_CTX hmc = {0};
    CRYPTO_OCTET cmp_mac[HASH_DIGEST_SIZE];

    CRYPTO_OCTET ct_len_repr[sizeof(CRYPTO_WORD)];
    for (size_t i = 0; i < sizeof(CRYPTO_WORD); ++i)
        ct_len_repr[i] = ct_len >> (8 * i);

    CRYPTO_OCTET ad_len_repr[sizeof(CRYPTO_WORD)];
    for (size_t i = 0; i < sizeof(CRYPTO_WORD); ++i)
        ad_len_repr[i] = ad_len >> (8 * i);

    hmac_init(&hmc, key);
    cipher_ctr(key, nonce, ct, ct_len, pt);
    hmac_update(&hmc, nonce, NONCE_SIZE);
    hmac_update(&hmc, ct_len_repr, sizeof(CRYPTO_WORD));
    hmac_update(&hmc, ct, ct_len);
    hmac_update(&hmc, ad_len_repr, sizeof(CRYPTO_WORD));
    hmac_update(&hmc, ad, ad_len);
    hmac_final(&hmc, cmp_mac);

    return util_const_compare(cmp_mac, mac, HASH_DIGEST_SIZE);
}
