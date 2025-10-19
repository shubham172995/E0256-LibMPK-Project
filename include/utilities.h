#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

void SecureZero(void *ptr, size_t len);

/* Provide explicit_bzero macro if not present on this platform.
   This makes your existing calls to explicit_bzero(...) work.
   If the platform already provides explicit_bzero, we don't redefine it. */
#ifndef explicit_bzero
#define explicit_bzero(ptr, len) secure_zero((ptr), (len))
#endif

bool CheckZeroBytes(uint8_t* buf, size_t size);