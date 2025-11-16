// block_pkey_allow_lib.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>

typedef int (*pkey_set_t)(int, unsigned int);

static pkey_set_t real_pkey_set(void) 
{
    static pkey_set_t fn = NULL;
    if (!fn) 
    {
        fn = (pkey_set_t)dlsym(RTLD_NEXT, "pkey_set");
    }
    return fn;
}

/* get resolved filename owning a return address */
static const char *owner_of_addr(void *addr) 
{
    static Dl_info info;
    if (!addr) 
        return NULL;
    if (dladdr(addr, &info) == 0)
         return NULL;
    return info.dli_fname; // pointer into dl_info internal storage (valid until next dladdr)
}

/* Compare allowed module list: ALLOW_PKEY_MODULE can be set to
   - a full path (/full/path/libtrusted.so) OR
   - a basename (libtrusted.so)
   Can also allow comma-separated list. */
static int caller_allowed(void *retaddr) {
    const char *allow = getenv("ALLOW_PKEY_MODULE");
    if (!allow || !allow[0]) 
        return 0; // no allowed modules => deny by default

    const char *owner = owner_of_addr(retaddr);
    if (!owner) 
        return 0;

    // allow comma-separated entries: try match basename or full path
    char *copy = strdup(allow);
    if (!copy) 
        return 0;
    char *token = strtok(copy, ",");
    while (token) 
        {
        // trim whitespace
        while (*token == ' ') 
            token++;
        size_t tlen = strlen(token);
        // exact match full path
        if (strcmp(owner, token) == 0) 
        { 
            free(copy); 
            return 1; 
        }
        // compare basename
        const char *b = strrchr(owner, '/');
        const char *ownerbase = b ? b+1 : owner;
        if (strcmp(ownerbase, token) == 0) 
        {
            free(copy); 
            return 1; 
        }
        // allow token that is a substring (looser)
        if (strstr(owner, token) != NULL) 
        { 
            free(copy); 
            return 1; 
        }

        token = strtok(NULL, ",");
    }
    free(copy);
    return 0;
}

/* wrapper */
int pkey_set(int pkey, unsigned int rights) 
{
    void *ret = __builtin_return_address(0);
    if (caller_allowed(ret)) 
    {
        pkey_set_t fn = real_pkey_set();
        if (!fn) 
        {
            errno = ENOSYS;
            return -1;
        }
        return fn(pkey, rights);
    }

    fprintf(stderr, "[block_pkey] blocked pkey_set from %p (caller_owner=%s)\n",
            ret, owner_of_addr(ret) ? owner_of_addr(ret) : "<unknown>");
    errno = EPERM;
    return -1;
}
