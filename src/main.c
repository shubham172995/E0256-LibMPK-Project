#include "trusted_crypto.h"
#include "utilities.h"
#include "envelope.h"


const size_t msgLen = 64;   //  Plaintext will be 64B for now.
const size_t nrOfMsgs = 100; //  currentNrOfKeys is 16 for now. Using a non-multiple  of 16 to handle asymmetry.

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
    if(TrustedInit())
    {
        printf("Init failed. Check if mmap failed.\n");
        return 1;
    }
    char** msgs = malloc(nrOfMsgs * sizeof(char*));  // fixed-size 2D array.
    CipherEnvelope **cipherEnvelope = malloc(nrOfMsgs * sizeof(*cipherEnvelope));

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
        cipherEnvelope[msgIndex]->ciphertextLen = strlen(msgs[msgIndex]); 

        cipherEnvelope[msgIndex]->ciphertext = (uint8_t*)malloc(cipherEnvelope[msgIndex]->ciphertextLen);
        cipherEnvelope[msgIndex]->ciphertextLen = EncryptData((uint8_t*)msgs[msgIndex], strlen(msgs[msgIndex]), cipherEnvelope[msgIndex]);
        uint32_t expectedDecryptedLen = cipherEnvelope[msgIndex]->ciphertextLen + 1;
        uint8_t* decrypted = (uint8_t*) malloc(expectedDecryptedLen);
        uint32_t decryptedLen = DecryptData(cipherEnvelope[msgIndex], decrypted, expectedDecryptedLen);
        decrypted[decryptedLen] = '\0';
        
        printf("Original: %s\n", msgs[msgIndex]);
        printf("Decrypted: %s\n", decrypted);
        free(decrypted);
    }

    //  Testing that a particular message with different key id fails.
    printf("\n\nRetesting for sanity\n");

    printf("\n\n\nAdding a negative testcase that tells that message encrypted with other key cannot decrypt it back\n");
    printf("Original: %s\n", msgs[6]);
    cipherEnvelope[6]->keyId = cipherEnvelope[6]->keyId + 2;
    uint32_t expectedDecryptedLen = cipherEnvelope[6]->ciphertextLen + 1;
    uint8_t* decrypted = (uint8_t*) malloc(expectedDecryptedLen);
    uint32_t decryptedLen = DecryptData(cipherEnvelope[6], decrypted, expectedDecryptedLen);
    printf("Decrypted Len : %d and Expected : %u\n", decryptedLen, expectedDecryptedLen);
    printf("Decrypted: %s\n", decrypted);
    free(decrypted);

    printf("\n\nTrying again with fixed key ID\n");
    printf("Original: %s\n", msgs[6]);
    cipherEnvelope[6]->keyId = cipherEnvelope[6]->keyId - 2;
    decrypted = (uint8_t*) malloc(expectedDecryptedLen);
    decryptedLen = DecryptData(cipherEnvelope[6], decrypted, expectedDecryptedLen);
    printf("Decrypted Len : %d and Expected : %u\n", decryptedLen, expectedDecryptedLen);
    printf("Decrypted: %s\n", decrypted);
    free(decrypted);

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
    ClearMappedPages();

    return 0;
}
