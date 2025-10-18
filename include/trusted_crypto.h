#ifndef TRUSTED_CRYPTO_H
#define TRUSTED_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

// Generate random AES key (128-bit)
void generate_key(uint8_t *key, size_t key_len);

// AES-GCM encrypt/decrypt
int encrypt_data(const uint8_t *plaintext, size_t plaintext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t *ciphertext, uint8_t *tag);

int decrypt_data(const uint8_t *ciphertext, size_t ciphertext_len,
                 const uint8_t *key, const uint8_t *iv,
                 const uint8_t *tag, uint8_t *plaintext);

#endif
