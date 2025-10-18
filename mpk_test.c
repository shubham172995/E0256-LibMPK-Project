// mpk_test.c
// Minimal MPK smoke-test. Compile on an Intel Linux machine with modern glibc.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <syscall.h>   // for SYS_pkey_alloc if needed
#include <linux/mman.h> // for pkey constants (optional)

static sigjmp_buf jmpbuf;
static volatile sig_atomic_t saw_segv = 0;

static void handler(int sig, siginfo_t *si, void *unused) {
    (void)si; (void)unused;
    saw_segv = 1;
    siglongjmp(jmpbuf, 1);
}

// Inline RD/WR PKRU helpers (opcode bytes)
static inline uint32_t read_pkru(void) {
    uint32_t pkru;
    asm volatile(".byte 0x0f,0x01,0xee" : "=a"(pkru) : "c"(0), "d"(0));
    return pkru;
}

static inline void write_pkru(uint32_t pkru) {
    asm volatile(".byte 0x0f,0x01,0xef" : : "a"(pkru), "c"(0), "d"(0));
}

// Wrapper for pkey_alloc + pkey_mprotect using library call if available
#ifdef __linux__
#include <sys/syscall.h>

static int alloc_pkey(void) {
#ifdef SYS_pkey_alloc
    long r = syscall(SYS_pkey_alloc, 0UL, 0UL);
    if (r < 0) return -1;
    return (int)r;
#else
    // If SYS_pkey_alloc not defined, try glibc function (may fail to link on older systems)
    // This will compile only if pkey_alloc exists in headers/libc.
    return pkey_alloc(0, 0);
#endif
}

static int set_pkey_for_range(void *addr, size_t len, int prot, int pkey) {
#ifdef SYS_pkey_mprotect
    long r = syscall(SYS_pkey_mprotect, addr, len, prot, pkey);
    if (r < 0) return -1;
    return 0;
#else
    return pkey_mprotect(addr, len, prot, pkey);
#endif
}
#else
#error "This test is for Linux only."
#endif

int main(void) {
    printf("[*] MPK smoke test\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    size_t pagesz = (size_t)sysconf(_SC_PAGESIZE);
    void *addr = mmap(NULL, pagesz, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    printf("[*] mmaped page at %p (pagesz=%zu)\n", addr, pagesz);

    int pkey = alloc_pkey();
    if (pkey < 0) {
        perror("pkey_alloc/syscall");
        printf("ERROR: pkey allocation failed. Kernel or glibc may not support pkeys.\n");
        munmap(addr, pagesz);
        return 2;
    }
    printf("[*] allocated pkey = %d\n", pkey);

    if (set_pkey_for_range(addr, pagesz, PROT_READ | PROT_WRITE, pkey) != 0) {
        perror("pkey_mprotect/syscall");
        printf("ERROR: pkey_mprotect failed. Are you on Linux with pkeys support?\n");
        munmap(addr, pagesz);
        return 3;
    }
    printf("[*] assigned pkey %d to page\n", pkey);

    volatile char *p = (volatile char*)addr;
    p[0] = 0x7f;
    printf("[*] wrote byte 0x7f to page, read back = 0x%02x\n", (unsigned char)p[0]);

    uint32_t old = read_pkru();
    printf("[*] initial PKRU = 0x%08x\n", old);

    // Build disable bits for this pkey: AD and WD bits set => bits = 3 for that key
    uint32_t disable_mask = (uint32_t)(3u << (2 * pkey));
    uint32_t newpkru = old | disable_mask;
    printf("[*] disabling access for pkey %d (mask 0x%08x)\n", pkey, disable_mask);
    write_pkru(newpkru);

    // Attempt read with SIGSEGV handling
    saw_segv = 0;
    if (sigsetjmp(jmpbuf, 1) == 0) {
        volatile unsigned char v = p[0]; // expected: SIGSEGV if PKU works
        // If we reach here, access succeeded
        printf("[!] Read succeeded while PKRU disabled: value=0x%02x\n", v);
    } else {
        printf("[*] Caught SIGSEGV while reading protected page (expected)\n");
    }

    // Restore PKRU
    write_pkru(old);
    printf("[*] restored PKRU to 0x%08x\n", old);

    // Read again
    printf("[*] read after restore = 0x%02x\n", (unsigned char)p[0]);

    // cleanup
    munmap(addr, pagesz);
    printf("[*] done\n");
    return 0;
}
