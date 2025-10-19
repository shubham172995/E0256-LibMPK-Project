#include "utilities.h"
#include "utilities.h"
#include <stddef.h>

#if defined(__has_include)
  #if __has_include(<openssl/crypto.h>)
    #define HAVE_OPENSSL_CLEANSE 1
    #include <openssl/crypto.h> /* OPENSSL_cleanse */
  #endif
#endif

#if defined(_WIN32)
  #include <windows.h>
  #define HAVE_SECUREZERO_WIN 1
#endif

void SecureZero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) return;

#if defined(HAVE_OPENSSL_CLEANSE)
    OPENSSL_cleanse(ptr, len);
    return;
#endif

#if defined(HAVE_SECUREZERO_WIN)
    SecureZeroMemory(ptr, len);
    return;
#endif

    /* fallback: volatile pointer write ensures the compiler won't optimize it away */
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}
/*
    Takes a buffer's start pointer and a size argument. Returns false if buffer has a non-zero byte.
*/

bool CheckZeroBytes(uint8_t* buf, size_t size)
{
    bool flag = true;
    for(size_t i = 0; i < size; ++i)
    {
        if(buf[i] != 0)
        {
            flag = false;
        }
    }
    return flag;
}