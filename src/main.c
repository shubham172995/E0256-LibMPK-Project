#include "trusted_crypto.h"
#include "utilities.h"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

const size_t tagSize = 16;  //  Using full sized tag.
const size_t ivSize = 12;   //  Using 12 Bytes of IV size recommended by NIST.
const size_t msgLen = 64;   //  Plaintext will be 64B for now.
const size_t nrOfMsgs = 100; //  nrOfKeys is 16 for now. Using a non-multiple  of 16 to handle asymmetry.



typedef struct {
    uint32_t keyId;            // which key was used (not secret)
    uint8_t iv[ivSize];             // nonce used (not secret)
    uint8_t tag[tagSize];            // authentication tag (MAC)
    uint8_t *ciphertext;        // pointer to ciphertext buffer
    size_t ciphertextLen;      // ciphertext length (same as plaintext)
} CipherEnvelope;

/*
    Generates multiple keys for our purpose.
*/
void GenerateKeys(uint8_t* mappedRegion, uint16_t nrOfKeys, size_t keyLen, uint32_t mappedRegionOffset)
{
    for(uint32_t keyIndex = 0; keyIndex < nrOfKeys; ++keyIndex)
    {
        //  Using this to make sure that keys are unique.
        while(true)
        {
            bool uniqueFound = true;
            generate_key(mappedRegion + mappedRegionOffset, keyLen);

            if(CheckZeroBytes(mappedRegion + mappedRegionOffset, keyLen))
            {
                //  returns true if bytes are 0.
                continue;
            }

            for (size_t off = 0; off < mappedRegionOffset; off += keyLen) {
                uint8_t *existing = mappedRegion + off; //  'existing' points to the page. Check once that MPK should protect this read.
                if (memcmp((mappedRegion + mappedRegionOffset), existing, keyLen) == 0) {
                    uniqueFound = false;
                    break;
                }
            }
            if(uniqueFound)
            {
                break;
            }
        }
        mappedRegionOffset += keyLen;
    }
}

/*
    ****************************************************** TO DO ******************************************************

    Using pageSize/16 (Using AES-128. So, 16B keys) ciphertexts generation for now. 
    Will change it to user specified input as well.
    We can take user input for number of pages to map and protect as well.
    So, we can make this input depend on that as well.

    Currently, generating 16 different keys. Can use user-dependent arg as well.

    Also, for MAC, page-size if 16 KB and for x86, it is 4 KB.

    Can also take user input for whether to use AES-128 or AES-256.
*/

int main() {
    size_t pageSize = (size_t)sysconf(_SC_PAGESIZE);
    size_t keyLen = aes128KeyLen; // Using AES-128
    uint16_t nrOfKeys = 16; //  Will use user provided arg if required. For now, use this.
    uint32_t maxNrOfKeys = pageSize/keyLen;
    uint8_t* mappedRegion;
    uint32_t mappedRegionOffset = 0;
    char** msgs = malloc(nrOfMsgs * sizeof(char*));  // fixed-size 2D array.
    CipherEnvelope **cipherEnvelope = malloc(nrOfMsgs * sizeof(*cipherEnvelope));

    //  mmap one page
    mappedRegion = mmap(NULL, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);  //  We will protect this page using libMPK later.

    if (mappedRegion == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    if(nrOfKeys > maxNrOfKeys)
    {
        nrOfKeys = maxNrOfKeys;
    }

    GenerateKeys(mappedRegion, nrOfKeys, keyLen, mappedRegionOffset);

    for (uint32_t msgIndex = 0; msgIndex < nrOfMsgs; ++msgIndex) 
    {
        /*  snprintf adds a \0 towards the end. If the size of string is > msgLen-1, 
            it will be truncated safely and last byte will be \0.
            Also, for now, assuming each message will be encrypted with a different key.
        */
        char tempMsg[msgLen];
        snprintf(tempMsg, msgLen, "Hello, data number %d", msgIndex);
        size_t strSize = strlen(tempMsg) + 1; // include '\0'
        msgs[msgIndex] = (char*)malloc(strSize);
        if (msgs[msgIndex] == NULL) {
            perror("malloc failed");
            exit(EXIT_FAILURE);
        }

        memcpy(msgs[msgIndex], tempMsg, strSize);
    }

    for (uint32_t msgIndex = 0; msgIndex < nrOfMsgs; ++msgIndex)
    {
        cipherEnvelope[msgIndex] = malloc(sizeof(CipherEnvelope));
        cipherEnvelope[msgIndex]->keyId = msgIndex % nrOfKeys;
        cipherEnvelope[msgIndex]->ciphertextLen = sizeof(msgs[msgIndex]); 

        //  Using a random IV. The loop ensure unniqueness.
        //  Using this to make sure that IVs are unique.
        while(true)
        {
            bool uniqueFound = true;
            generate_key(cipherEnvelope[msgIndex]->iv, sizeof(cipherEnvelope[msgIndex]->iv)); // reusing RAND_bytes wrapper for initializing IV as well.

            if(CheckZeroBytes(cipherEnvelope[msgIndex]->iv, sizeof(cipherEnvelope[msgIndex]->iv)))
            {
                //  returns true if bytes are 0.
                continue;
            }

            for (size_t off = 0; off < msgIndex; ++off) {
                if (memcmp(cipherEnvelope[msgIndex]->iv, cipherEnvelope[off]->iv, sizeof(cipherEnvelope[msgIndex]->iv)) == 0) {
                    uniqueFound = false;
                    break;
                }
            }
            if(uniqueFound)
            {
                break;
            }
        }

        cipherEnvelope[msgIndex]->ciphertext = (uint8_t*)malloc(cipherEnvelope[msgIndex]->ciphertextLen);
        cipherEnvelope[msgIndex]->ciphertextLen = encrypt_data((uint8_t*)msgs[msgIndex], strlen(msgs[msgIndex]), (mappedRegion + (msgIndex % nrOfKeys)*keyLen), cipherEnvelope[msgIndex]->iv, cipherEnvelope[msgIndex]->ciphertext, cipherEnvelope[msgIndex]->tag);
        uint8_t* decrypted = (uint8_t*) malloc(cipherEnvelope[msgIndex]->ciphertextLen + 1);
        uint32_t decryptedLen = decrypt_data(cipherEnvelope[msgIndex]->ciphertext, cipherEnvelope[msgIndex]->ciphertextLen, (mappedRegion + (msgIndex % nrOfKeys)*keyLen), cipherEnvelope[msgIndex]->iv, cipherEnvelope[msgIndex]->tag, decrypted);
        decrypted[decryptedLen] = '\0';
        
        printf("Original: %s\n", msgs[msgIndex]);
        printf("Decrypted: %s\n", decrypted);
        free(decrypted);
    }

    //  Cleanup
    memset(mappedRegion, 0, keyLen);
    munmap(mappedRegion, pageSize);

     // Free
    for (uint32_t i = 0; i < nrOfMsgs; ++i) 
    {
        SecureZero(cipherEnvelope[i]->ciphertext, cipherEnvelope[i]->ciphertextLen);
        free(cipherEnvelope[i]->ciphertext);
        SecureZero(cipherEnvelope[i], sizeof(CipherEnvelope)); // wipe metadata if desired
        free(cipherEnvelope[i]);
        SecureZero(msgs[i], strlen(msgs[i]));
        free(msgs[i]);
    }
    free(cipherEnvelope);
    free(msgs);

    return 0;
}
