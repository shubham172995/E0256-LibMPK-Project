#ifndef TRUSTED_CRYPTO_H
#define TRUSTED_CRYPTO_H

#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include "utilities.h"
#include "envelope.h"

typedef uint32_t keyId_t;

typedef struct {
    keyId_t id;
    void *addressOfKeyInpage;          // mmap'd page pointer holding the key bytes
    size_t keyLen;
    bool active;
    uint16_t nrOfIVs;
    uint8_t* arrayOfIVs;    //  12 bytes of IV. This points to (nrOfIVs) of IVs.
    int pkey;            // pkey id or -1. To be used after MPK is incorporated.
    /*
    uint64_t seq_ctr;    // nonce counter
    uint32_t flags;      // usage
    time_t created;
    pthread_mutex_t lock; // protect per-key metadata (optional)
    */
} keyEntry;

//  static because these are compile time constants. This header is being called in multiple .c files.
static const size_t aes128KeyLen = 16;
static const size_t aes256KeyLen = 32;

//  ****** TO DO ******* :- make this const and use properly.
//const uint16_t nrOfKeys = 16; //  Will use user provided arg if required. For now, use this.

//  Init function.
int TrustedInit();

// Generate random AES key (128-bit)
int GenerateKey(uint8_t *key, size_t key_len);

uint16_t GetNrOfKeys();

void GenerateKeys(uint8_t* mappedRegion, uint16_t nrOfKeys, size_t keyLen, uint32_t mappedRegionOffset, int pkey);

int GenerateIVForKeyIndex(uint16_t keyIndexToBeUsed);

// AES-GCM encrypt/decrypt
int EncryptData(const uint8_t *plaintext, size_t plaintext_len,
                CipherEnvelope* inEnvelope);//, bool isNewKeyNeeded = false);

int DecryptData(const CipherEnvelope* inEnvelope,
                uint8_t *plaintext, size_t plaintextBufLen);

void ClearMappedPages();

int my_pkey_set(int pkey, unsigned int rights);

#endif
