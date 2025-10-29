#include "trusted_crypto.h"

//  Defining these as this for now. We might change these later on.
#define maxNrOfKeyPages      15   //  MPK supports 16 pages.
#define initialNrOfKeyPages  12   //  Start with these many. Add more till max if needed.
#define maxNrOfKeysPerPage   32   //  To be used later. For now, 1 page has 1 key.

static keyEntry* keyEntryTable[maxNrOfKeysPerPage * maxNrOfKeyPages];  //  Maximum number of keys is 8192. 32 (per page) * 15 (max nr of pages).
static size_t keyIndexToBeUsed = 0;
static size_t nrOfKeysCreated = 0;
static uint8_t* mappedPageAddresses[maxNrOfKeyPages];   //  This stores the starting addresses of mmap()'d pages. Helps when unmapping them.
static int mappedPagePkeys[maxNrOfKeyPages];   //  This stores the starting addresses of mmap()'d pages. Helps when unmapping them.

int GenerateKey(uint8_t *key, size_t keyLen) 
{
    if (RAND_bytes(key, keyLen) != 1) {
        fprintf(stderr, "Error generating random key\n");
        return -1;
    }
    return 1;
}

int GenerateIV(uint8_t *iv, size_t ivLen) 
{
    if (RAND_bytes(iv, ivLen) != 1) {
        fprintf(stderr, "Error generating random IV\n");
        return -1;
    }
    return 1;
}

/*
    Generates multiple keys for our purpose.
*/
void GenerateKeys(uint8_t* mappedRegion, uint16_t nrOfKeys, size_t keyLen, uint32_t mappedRegionOffset)
{
    /*
        ****************************************************** TO DO ******************************************************

        Add IV generation per key.
    */
    for(uint32_t keyIndex = 0; keyIndex < nrOfKeys; ++keyIndex)
    {
        //  Using this to make sure that keys are unique.
        while(true)
        {
            bool uniqueFound = true;
            if(-1 == GenerateKey(mappedRegion + mappedRegionOffset, keyLen))
            {
                continue;
            }

            if(CheckZeroBytes(mappedRegion + mappedRegionOffset, keyLen))
            {
                //  returns true if bytes are 0.
                continue;
            }

            for (size_t off = 0; off < nrOfKeysCreated; ++off) {
                keyEntry *existing = keyEntryTable[off]; //  'existing' points to the earlier key. Check once that MPK should protect this read.
                if(keyLen == existing->keyLen)  //  Proceed only if keyLen of this key is keyLen of current key.
                {
                    if (memcmp((mappedRegion + mappedRegionOffset), existing->addressOfKeyInpage, keyLen) == 0)
                    {
                        uniqueFound = false;
                        break;
                    }
                }
            }

            /*
                        THIS WAS USED EARLIER TO FIND IF KEYS AMONG A PAGE HELD DUPLICATES. NOW, WITH keyEntry table,
                        this approach is not required. Still, leaving it commented. Could be useful.

            for (size_t off = 0; off < mappedRegionOffset; off += keyLen) {
                uint8_t *existing = mappedRegion + off; //  'existing' points to the page. Check once that MPK should protect this read.
                if (memcmp((mappedRegion + mappedRegionOffset), existing, keyLen) == 0) {
                    uniqueFound = false;
                    break;
                }
            }
            */
            if(uniqueFound)
            {
                break;
            }
        }
        keyEntryTable[nrOfKeysCreated] = (keyEntry*)malloc(sizeof(keyEntry));
        keyEntryTable[nrOfKeysCreated]->keyLen = keyLen;
        keyEntryTable[nrOfKeysCreated]->active = true;
        keyEntryTable[nrOfKeysCreated]->addressOfKeyInpage = (mappedRegion + mappedRegionOffset);
        keyEntryTable[nrOfKeysCreated]->id = nrOfKeysCreated;
        keyEntryTable[nrOfKeysCreated]->nrOfIVs = 0;
        ++nrOfKeysCreated;
        mappedRegionOffset += keyLen;
    }
}

uint16_t GetNrOfKeys()
{
    return nrOfKeysCreated;
}

int GenerateIVForKeyIndex(uint16_t keyIndexToBeUsed)
{
    uint16_t nrOfIVs = keyEntryTable[keyIndexToBeUsed]->nrOfIVs;
    uint8_t* newArrayOfIVs = realloc(keyEntryTable[keyIndexToBeUsed]->arrayOfIVs, (nrOfIVs + 1) * ENVELOPE_IV_LEN); 

    if(!newArrayOfIVs)
    {
        return -1;
    }

    keyEntryTable[keyIndexToBeUsed]->arrayOfIVs = newArrayOfIVs;

    uint8_t* iv = keyEntryTable[keyIndexToBeUsed]->arrayOfIVs + (nrOfIVs * ENVELOPE_IV_LEN);

    //  Using a random IV. The loop ensure unniqueness.
    //  Using this to make sure that IVs are unique.
    while(true)
    {
        bool uniqueFound = true;
        if(-1 == GenerateIV(iv, ENVELOPE_IV_LEN)) // using RAND_bytes wrapper for initializing IV as well.
        {
            continue;
        }

        if(CheckZeroBytes(iv, ENVELOPE_IV_LEN))
        {
            //  returns true if bytes are 0.
            continue;
        }

        for (size_t off = 0; off < nrOfIVs; ++off) 
        {
            uint8_t *existing = keyEntryTable[keyIndexToBeUsed]->arrayOfIVs + (off * ENVELOPE_IV_LEN);
            if (memcmp(iv, existing, ENVELOPE_IV_LEN) == 0) {
                uniqueFound = false;
                break;
            }
        }
        if(uniqueFound)
        {
            break;
        }
    }
    ++(keyEntryTable[keyIndexToBeUsed]->nrOfIVs)
    ;
    return 1;
}

/*
 * Encrypt plaintext -> ciphertext using AES-GCM.
 * - plaintext_len: bytes of plaintext
 * - ciphertext: output buffer (must be at least plaintext_len bytes)
 * - tag: output buffer for tag (must be at least 16 bytes)
 *
 * Returns ciphertext length on success (== plaintext_len), or -1 on error.
 */
int EncryptData(const uint8_t *plaintext, size_t plaintext_len,
                CipherEnvelope* inEnvelope)//, bool isNewKeyNeeded = false)
{
    if (!plaintext || !inEnvelope) return -1;

    for(uint16_t keyIndex = keyIndexToBeUsed; keyIndex < nrOfKeysCreated; keyIndex = (keyIndex + 1) % nrOfKeysCreated)
    {
        //  Modulus nrOfKeysCreated because we use round robin for encryption.
        if(keyEntryTable[keyIndex] && keyEntryTable[keyIndex]->active)
        {
            keyIndexToBeUsed = keyIndex;
            break;
        }
    }
    inEnvelope->keyId = keyIndexToBeUsed;
    if(-1 == GenerateIVForKeyIndex(keyIndexToBeUsed))
    {
        printf("realloc failed for allocating space for a new IV corresponding to this key\n");
        return -1;
    }

    //  Dereference can be done since we checked above that this is legit index.
    const uint8_t *key = keyEntryTable[keyIndexToBeUsed]->addressOfKeyInpage;
    size_t keyLen = keyEntryTable[keyIndexToBeUsed]->keyLen;

    const EVP_CIPHER *cipher = (keyLen == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    int len = 0;
    int outlen = 0;
    uint8_t* iv = keyEntryTable[keyIndexToBeUsed]->arrayOfIVs + (ENVELOPE_IV_LEN * (keyEntryTable[keyIndexToBeUsed]->nrOfIVs - 1));
    memcpy(inEnvelope->iv, iv, ENVELOPE_IV_LEN);

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) goto cleanup;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ENVELOPE_IV_LEN, NULL)) goto cleanup;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, inEnvelope->iv)) goto cleanup;

    if (plaintext_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, inEnvelope->ciphertext, &len, plaintext, (int)plaintext_len)) goto cleanup;
        outlen = len;
    } else {
        outlen = 0;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, inEnvelope->ciphertext + outlen, &len)) goto cleanup;
    outlen += len;

    /* Get tag (default 16 bytes). If you want a different tag size, set it via EVP_CIPHER_CTX_ctrl */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ENVELOPE_TAG_LEN, inEnvelope->tag)) goto cleanup;

    ret = outlen; /* success */
    keyIndexToBeUsed = (keyIndexToBeUsed + 1) % nrOfKeysCreated;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * DecryptData: AES-GCM decrypt wrapper
 *
 * Inputs:
 *  - Cipher Envelope input,
 *  - plaintext: output buffer, 
 *  - plaintextBufLen must be >= ciphertextLen
 *
 * Returns:
 *  - plaintext length (== ciphertextLen) on success
 *  - -2 on authentication failure (tag mismatch)
 *  - -1 on other errors (invalid args, OpenSSL error, buffer too small)
 */
int DecryptData(const CipherEnvelope* inEnvelope,
                uint8_t *plaintext, size_t plaintextBufLen)
{
    if (!inEnvelope || !plaintext) return -1;

    const uint8_t *iv, *tag, *ciphertext, *key;
    size_t ciphertextLen, keyLen;
    uint32_t keyId;

    iv = inEnvelope->iv;
    tag = inEnvelope->tag;
    ciphertext = inEnvelope->ciphertext;
    ciphertextLen = inEnvelope->ciphertextLen;
    keyId = inEnvelope->keyId;

    key = keyEntryTable[keyId]->addressOfKeyInpage;
    keyLen = keyEntryTable[keyId]->keyLen;

    if (ciphertextLen > plaintextBufLen) return -1;
    if (ciphertextLen > (size_t)INT_MAX) return -1; // safe casting

    const EVP_CIPHER *cipher = (keyLen == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    int len = 0;
    int outlen = 0;
    int rv;

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) goto cleanup;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ENVELOPE_IV_LEN, NULL)) goto cleanup;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto cleanup;

    /* ciphertext -> plaintext */
    if (ciphertextLen > 0) {
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertextLen)) goto cleanup;
        outlen = len;
    } else {
        outlen = 0;
    }

    /* set expected tag value before finalizing */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ENVELOPE_TAG_LEN, (void *)tag)) goto cleanup;

    /* Finalize — returns 1 if tag valid, 0 if tag invalid */
    rv = EVP_DecryptFinal_ex(ctx, plaintext + outlen, &len);
    if (rv > 0) {
        outlen += len;
        ret = outlen; /* success */
    } else {
        /* authentication failed */
        ret = -2;
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int TrustedInit()
{
    size_t pageSize = (size_t)sysconf(_SC_PAGESIZE);
    for(uint16_t pageIndex = 0; pageIndex < initialNrOfKeyPages; ++pageIndex)
    {
        size_t keyLen = (pageIndex % 2) ? aes128KeyLen : aes256KeyLen; // Using AES-128 for even and 256 for odd indexed pages.
        uint16_t nrOfKeys = 1 + (pageIndex % 16); //  For now, using this to assign 1 + (pageIndex % 16) keys to page indexed at pageIndex
        uint32_t maxKeyCapForThisPage = pageSize/keyLen;
        uint32_t mappedRegionOffset = 0;

        //  mmap one page
        mappedPageAddresses[pageIndex] = mmap(NULL, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);  //  We will protect this page using libMPK later.

        if (mappedPageAddresses[pageIndex] == MAP_FAILED)
        {
            perror("mmap");
            return 1;
        }

        if(nrOfKeys > maxKeyCapForThisPage)
        {
            nrOfKeys = maxKeyCapForThisPage;
        }

        /* allocate a protection key: initial rights mask PKEY_DISABLE_WRITE (example) */
        int pkey = pkey_alloc(0, PKEY_DISABLE_ACCESS);
        if (pkey == -1) 
        { 
            perror("pkey_alloc"); 
            munmap(mappedPageAddresses[pageIndex], pageSize); 
            return 1; 
        }
        //  printf("allocated pkey = %d\n", pkey);

        /* attach the key to the VMA and set normal read+write permissions for the page */
        if (pkey_mprotect(mappedPageAddresses[pageIndex], pageSize, PROT_READ | PROT_WRITE, pkey) == -1) {
            perror("pkey_mprotect");
            pkey_free(pkey);
            munmap(mappedPageAddresses[pageIndex], pageSize);
            return 1;
        }
        puts("attached pkey and set PROT_READ|PROT_WRITE");

        /* At this point the page has R/W in page tables but the thread's PKRU
        can disable write access for this pkey. Because we allocated the key
        with PKEY_DISABLE_WRITE, the key starts with writes disabled. */

        /* attempt to enable write for this thread (clear the disable flag) */
        if (pkey_set(pkey, 0) == -1) 
        { 
            perror("pkey_set(enable)"); 
        }
        else 
        {
            printf("pkey_set(%d,0): write enabled for this thread — writing...\n", pkey);
            GenerateKeys(mappedPageAddresses[pageIndex], nrOfKeys, keyLen, mappedRegionOffset);               /* should succeed */
            printf("GenerateKeys() successful\n");
        }
        mappedPagePkeys[pageIndex] = pkey;
    }
    /* now re-disable write for this pkey in this thread */
    for(uint16_t pageIndex = 0; pageIndex < initialNrOfKeyPages; ++pageIndex)
    {
        if (pkey_set(mappedPagePkeys[pageIndex], PKEY_DISABLE_ACCESS) == -1)
        {
            perror("pkey_set(disable)");   
        }
        else 
        {
            puts("re-disabled write for this thread");
        }
    }
    
    return 0;
}

void ClearMappedPages()
{
    size_t pageSize = (size_t)sysconf(_SC_PAGESIZE);
    for(uint16_t pageIndex = 0; pageIndex < initialNrOfKeyPages; ++pageIndex)
    {
        munmap(mappedPageAddresses[pageIndex], pageSize);
        if (pkey_free(mappedPagePkeys[pageIndex]) == -1) 
            perror("pkey_free");
    }
}