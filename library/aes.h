#pragma once
#include "mbedtls/aes.h"
#include <string.h>
#include <stdint.h>

int aes_decrypt(mbedtls_aes_context* ctx, uint8_t* key, int key_len, uint8_t* input, uint8_t* output)
{
    if (key_len!=16 && key_len!=32)
        return -1;
    mbedtls_aes_setkey_dec(ctx, key, key_len*8);
    return mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_DECRYPT, input, output);
}

int aes_encrypt(mbedtls_aes_context* ctx, uint8_t* key, int key_len, uint8_t* input, uint8_t* output)
{
    if (key_len!=16 && key_len!=32)
        return -1;
    mbedtls_aes_setkey_enc(ctx, key, key_len*8);
    return mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, input, output);
}