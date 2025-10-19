#include "trusted_crypto.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
 
/* 
void TrustedInit()
{
    
}
*/

void generate_key(uint8_t *key, size_t key_len) {
    if (RAND_bytes(key, key_len) != 1) {
        fprintf(stderr, "Error generating random key\n");
    }
}

int encrypt_data(const uint8_t *plaintext, size_t plaintext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t *ciphertext, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_data(const uint8_t *ciphertext, size_t ciphertext_len,
                 const uint8_t *key, const uint8_t *iv,
                 const uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len = 0, ret;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) return plaintext_len + len;
    else return -1; // Decryption failed (tag mismatch)
}
