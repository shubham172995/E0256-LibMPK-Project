#ifndef TRUSTED_CRYPTO_H
#define TRUSTED_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "utilities.h"

typedef uint32_t keyId_t;

typedef struct {
    keyId_t id;
    void *page;          // mmap'd page pointer holding the key bytes
    size_t keyLen;
    /*
    int pkey;            // pkey id or -1. To be used after MPK is incorporated.
    uint64_t seq_ctr;    // nonce counter
    uint32_t flags;      // usage
    time_t created;
    bool active;
    pthread_mutex_t lock; // protect per-key metadata (optional)
    */
} keyEntry;

//  static because these are compile time constants. This header is being called in multiple .c files.
static const size_t aes128KeyLen = 16;
static const size_t aes256KeyLen = 32;
//  ****** TO DO ******* :- make this const and use properly.
//const uint16_t nrOfKeys = 16; //  Will use user provided arg if required. For now, use this.

//  Init function.
void TrustedInit();

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
