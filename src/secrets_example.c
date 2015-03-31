#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <gnu/lib-names.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <string.h>

#include "secrets.h"

int main() {
   void *glibc = NULL;
   static glibc_context_t ctx;
   memset(&ctx, 0, sizeof(glibc_context_t));

    glibc = dlopen(LIBC_SO, RTLD_LAZY);

    if (!glibc) {
        fprintf(stderr, "FATAL libc load error.\n");
        /* TODO: panic better */
        return;
    }

    ctx.glibc          = glibc;
    ctx.glibc_getenv   = dlsym(glibc, "getenv");
    ctx.glibc_setenv   = dlsym(glibc, "setenv");
    ctx.glibc_unsetenv = dlsym(glibc, "unsetenv");
    ctx.glibc_execve   = dlsym(glibc, "execve");
    ctx.glibc_readlink = dlsym(glibc, "readlink");

    secrets_t *secrets_ctx = secrets_new(&ctx);
}
