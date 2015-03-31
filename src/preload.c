#include <stdio.h>
#include <stdlib.h>
#include <gnu/lib-names.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <string.h>

#include "cdecode.h"
#include "cencode.h"
#include "secrets.h"

/*
 * Define initializion constructor when secrets is loaded.
 */
static void            load_glibc(void) __attribute__ ((__constructor__));

static glibc_context_t global_libc_ctx;
static secrets_t     * global_secrets_ctx = NULL;

static void
load_glibc(void) {
    void *glibc = NULL;

    memset(&global_libc_ctx, 0, sizeof(glibc_context_t));

    glibc = dlopen(LIBC_SO, RTLD_NOW | RTLD_GLOBAL);

    if (!glibc) {
        fprintf(stderr, "FATAL libc load error.\n");
        /* TODO: panic better */
        return;
    }

    global_libc_ctx.glibc          = glibc;
    global_libc_ctx.glibc_getenv   = dlsym(glibc, "getenv");
    global_libc_ctx.glibc_setenv   = dlsym(glibc, "setenv");
    global_libc_ctx.glibc_unsetenv = dlsym(glibc, "unsetenv");
    global_libc_ctx.glibc_execve   = dlsym(glibc, "execve");
    global_libc_ctx.glibc_readlink = dlsym(glibc, "readlink");

    global_secrets_ctx = secrets_new(&global_libc_ctx);
}

/*
 * Function wrapper - execve()
 */
int
execve(const char *filename, char *const argv[], char *const envp[]) {
    int ret          = -1;

    /*
     * we unset decrypted secrets so they are not visible to the execve() call
     * and recorded to /proc/<pid>/environ.
     */
    char ** new_envp = secrets_unset_secrets((const char **)envp);

    if (new_envp == NULL) {
        new_envp = (char **)envp;
    }
    ret = global_libc_ctx.glibc_execve(filename, argv, new_envp);
    return ret;
}


/*
 * Custom getenv() will look for SECRET_<name> environment variable that
 * is encrypted.
 *
 * If this exists, attempts to lookup a decryption key using request_key()
 * in libkeyutils.
 *
 * It will then try to decrypt the key.
 */
//char *
//getenv(const char *name) {
//    char *result      = NULL;
//    char *secure_name = NULL;
//    char *secure_env  = NULL;
//
//    if (!name) {
//        return NULL;
//    }
//
//    result = global_libc_ctx.glibc_getenv(name);
//
//    if (!global_secrets_ctx) {
//        goto _getenv_end;
//    }
//
//    secure_name = secrets_get_secure_name(&global_secrets_ctx, name);
//
//    if (!secure_name) {
//        /* error, no secure name found */
//        return result;
//    }
//
//    if (!(secure_env = global_libc_ctx.glibc_getenv(secure_name))) {
//        goto _getenv_end;
//    }
//
//_getenv_end:
//    if (secure_name) {
//        free(secure_name);
//    }
//    secure_name = NULL;
//
//    fprintf(stderr, "getenv (\"%s\") = %s%s%s\n", name,
//            result ? "\"" : "",
//            result ? result : "NULL",
//            result ? "\"" : "");
//
//    return result;
//}



