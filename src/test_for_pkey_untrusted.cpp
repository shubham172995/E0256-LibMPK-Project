#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

int main() {
    int pkey = pkey_alloc(0, 0);
    if (pkey < 0) {
        perror("pkey_alloc failed");
        return 1;
    }

    printf("Allocated pkey = %d\n", pkey);

    // Try setting permissions:
    int ret = pkey_set(pkey, PKEY_DISABLE_WRITE);
    if (ret < 0) {
        perror("pkey_set failed");
    } else {
        printf("Successfully called pkey_set()\n");
    }

    // Free key
    pkey_free(pkey);
    return 0;
}
