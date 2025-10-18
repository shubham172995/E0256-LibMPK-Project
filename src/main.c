#include "trusted_crypto.h"
#include <stdio.h>
#include <string.h>

int main() {
    uint8_t key[16];
    uint8_t iv[12] = {0};
    uint8_t tag[16];
    uint8_t ciphertext[128], decrypted[128];

    generate_key(key, sizeof(key));

    const char *msg = "Confidential quantum data";
    int ciphertext_len = encrypt_data((uint8_t*)msg, strlen(msg), key, iv, ciphertext, tag);
    int decrypted_len = decrypt_data(ciphertext, ciphertext_len, key, iv, tag, decrypted);

    decrypted[decrypted_len] = '\0';
    printf("Original: %s\n", msg);
    printf("Decrypted: %s\n", decrypted);
}
