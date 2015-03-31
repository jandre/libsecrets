#include <stdio.h>
#include <stdlib.h>
#include <gnu/lib-names.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <string.h>
#include <keyutils.h>
#include <mcrypt.h>

#include "cdecode.h"
#include "cencode.h"

#include "secrets.h"

#define SECRETS_DEBUG 1

#ifdef  SECRETS_DEBUG
#define SECRETS_LOG(...) fprintf(stderr, "[SECRETS_DEBUG] "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");
#else
#define SECRETS_LOG(...)
#endif


#define MAX_SECRETS 1024

#define FREE_IF_NOT_NULL(var)       \
    do { if (var != NULL) {         \
             free(var); var = NULL; \
         }                          \
    } while (0);

MCRYPT _secrets_crypt_initialize(secrets_t *);

char * _secrets_lookup_app_key(secrets_t *);
char * _secrets_lookup_user_key(secrets_t *);
void   _secrets_set_encryption_key(secrets_t *, char * const);

size_t _secrets_encrypt_msg(secrets_t *, char *, char **);
size_t _secrets_decrypt_msg(secrets_t *, char *, size_t, char **);
size_t _secrets_decrypt_base64_msg_and_iv(secrets_t *, char *, char **);

int    _secrets_generate_random_string(char *, size_t);
char * _secrets_base64_encode(char *, size_t);
int    _secrets_base64_decode(char *, size_t, char *, size_t);
char * _secrets_get_base64_iv(secrets_t *);
char * _secrets_get_base64_app_key(secrets_t *);
char * _secrets_get_base64_user_key(secrets_t *);

int    _secrets_parse_key_eq_val( char, const char *, char *, size_t, char *, size_t );

/* provided by libc */
extern const char **__environ;
extern const char  *__progname;

/*
 * The app key stored in the environment variable
 *
 * It will current allocate a key, so must be freed.
 */
char *
_secrets_lookup_app_key(secrets_t * ctx) {
    char * val = ctx->glibc->glibc_getenv(SECRETS_ENV_KEY);

    if (val) {
        /*
         * TODO: fix this, I don't really have to do it
         * just matching _secrets_lookup_user_key
         */
        return strdup(val);
    }

    return NULL;
}

/*
 * The user key is stored in the kernel's keyutils keyring.
 *
 * It will current allocate a key, so must be freed.
 */
char *
_secrets_lookup_user_key(secrets_t * ctx) {
    key_serial_t enc_key_id    = 0;
    /* TODO: fetch from env variable as well. */
    const char * user_key_desc = SECRETS_KEYRING_DEFAULT_DESC;
    char       * key           = NULL;

    /* try to find the encryption key for the environment variables */
    enc_key_id = request_key(
        "user",
        user_key_desc,
        NULL,
        KEY_SPEC_PROCESS_KEYRING
        );

    /* TODO: is the key null terminated, or do we need to null terminate? */
    if (enc_key_id > 0) {
        size_t bytes = keyctl_read_alloc(enc_key_id, (void **)&key);
        if (key != NULL) {
            SECRETS_LOG("found user key: %s", key)
            return key;
        }
    }
    return NULL;
}

/*
 * initializes the crypto-related stuff in secrets_t
 */
MCRYPT
_secrets_crypt_initialize(secrets_t * ctx) {
    MCRYPT handle = 0;

    handle = mcrypt_module_open("blowfish", NULL, "cbc", NULL);

    if (handle == MCRYPT_FAILED) {
        SECRETS_LOG("mcrypt failed")
        return NULL;
    }

    ctx->iv_len             = mcrypt_enc_get_iv_size(handle);
    ctx->iv                 = calloc(1, ctx->iv_len);

    ctx->block_len          = mcrypt_enc_get_block_size(handle);
    ctx->block              = calloc(1, ctx->block_len);

    ctx->encryption_key_len = mcrypt_enc_get_key_size(handle);
    ctx->app_key            = calloc(1, ctx->encryption_key_len);
    ctx->user_key           = calloc(1, ctx->encryption_key_len);

    ctx->handle             = handle;

    return handle;
}

/*
 * free secrets_t resources
 */
void
secrets_free(secrets_t * ctx) {
    if (ctx->handle) {
        mcrypt_module_close(ctx->handle);
    }
    FREE_IF_NOT_NULL(ctx->app_key);
    FREE_IF_NOT_NULL(ctx->user_key);
    FREE_IF_NOT_NULL(ctx->iv);
    FREE_IF_NOT_NULL(ctx->block);
}

/*
 * decrypts msg, returns newly alloc'd data in outbuf
 */
size_t
_secrets_decrypt_msg(secrets_t * ctx, char * msg, size_t msg_len, char **outbuf) {
    int    err           = 0;
    size_t bytes_written = 0;
    size_t num_blocks    = 0;
    char * cur_block     = NULL;
    char   decryption_key[ctx->encryption_key_len];

    _secrets_set_encryption_key(ctx, decryption_key);

    if (msg == NULL) {
        return 0;
    }

    if (msg_len == 0) {
        return 0;
    }

    num_blocks = 1 + (msg_len / ctx->block_len);
    /* cur_block is a pointer to outbuf */
    cur_block  = *outbuf = calloc(1, msg_len);

    MCRYPT handle = ctx->handle;

    if (handle == MCRYPT_FAILED) {
        return 0;
    }

    err = mcrypt_generic_init(
        handle,
        decryption_key,
        ctx->encryption_key_len,
        ctx->iv);

    if (err) {
        SECRETS_LOG("mcrypt_generic_init err")
        goto _decrypt_msg_err;
    }

    while (msg_len > 0) {
        memset(ctx->block, 0, ctx->block_len);
        memcpy(ctx->block, msg, msg_len);

        err = mdecrypt_generic(handle, ctx->block, ctx->block_len);

        if (err) {
            SECRETS_LOG("decryption failed");
            break;
        }

        /* copy block to outbuf, then increment the block position */
        memcpy(cur_block, ctx->block, ctx->block_len);
        cur_block     += ctx->block_len;
        bytes_written += ctx->block_len;

        msg_len        = (msg_len > ctx->block_len) ?  msg_len - ctx->block_len : 0;

        if (msg_len > 0) {
            msg += ctx->block_len;
        }
    }

    goto _decrypt_msg_ok;

_decrypt_msg_err:
    FREE_IF_NOT_NULL(*outbuf)
    bytes_written = 0;
_decrypt_msg_ok:
    mcrypt_generic_deinit(handle);
    return bytes_written;
} /* _secrets_decrypt_msg */

/*
 * Given a msg like this:
 *
 * <base64 iv>$<base 64 msg>
 *
 * Will attempt to decrypt the value.
 */
size_t
_secrets_decrypt_base64_msg_and_iv(secrets_t * ctx, char *msg, char **outbuf) {
    size_t len            = strlen(msg);
    char   b64iv[len + 1]; /* XXX: conver to ptr */
    char   b64msg[len + 1];
    int    binary_msg_len = len * 2 + 1;
    char   binary_msg[binary_msg_len];
    int    err            = 0;
    int    bytes_written  = 0;

    err = _secrets_parse_key_eq_val(
        '$',
        msg,
        b64iv,
        len + 1,
        b64msg,
        len + 1);

    if (err) {
        /* failure to parse */
        SECRETS_LOG("parse failed: %d", err)
        return 0;
    }

    SECRETS_LOG("read iv=%s, msg=%s", b64iv, b64msg);

    if (!_secrets_load_base64_iv(ctx, b64iv)) {
        return 0;
    }
    /* base64 decrypt msg into buffer */
    if (!(bytes_written = _secrets_base64_decode((char *)&binary_msg, binary_msg_len,
                                                 (char *)&b64msg, 0))) {
        return 0;
    }

    bytes_written = _secrets_decrypt_msg(ctx, binary_msg, bytes_written, outbuf);

    return bytes_written;
} /* _secrets_decrypt_base64_msg_and_iv */

/*
 * Returns an encrypted msg like so:
 *
 * <base64 iv>$<base 64 msg>
 */
size_t
secrets_encrypt_msg_and_base64(secrets_t * ctx, char *msg, char **outbuf) {
    size_t total_len           = 0;
    char  *encrypted_bytes     = NULL;
    size_t encrypted_bytes_len = 0;
    char  *base64_iv           = NULL;
    size_t base64_iv_len       = 0;
    char  *base64_msg          = NULL;
    size_t base64_msg_len      = 0;

    encrypted_bytes_len = _secrets_encrypt_msg(ctx, msg, &encrypted_bytes);

    if (!encrypted_bytes_len || !encrypted_bytes) {
        SECRETS_LOG("encryption failed, no bytes returned.");
        return 0;
    }

    base64_msg     = _secrets_base64_encode(encrypted_bytes, encrypted_bytes_len);
    base64_msg_len = strlen(base64_msg);

    base64_iv      = _secrets_get_base64_iv(ctx);
    base64_iv_len  = strlen(base64_iv);

    total_len      = base64_iv_len + base64_msg_len + 2;
    *outbuf        = calloc(1, total_len);

    snprintf(*outbuf, total_len, "%s$%s", base64_iv, base64_msg);

    SECRETS_LOG("ecnrypted and base64 iv/msg%s", *outbuf)
    /* XXX TODO A LOT OF ERROR HANDLING */
    goto _ok;
_err:
    FREE_IF_NOT_NULL(*outbuf)
    total_len = 0;
_ok:
    FREE_IF_NOT_NULL(encrypted_bytes)
    FREE_IF_NOT_NULL(base64_msg)
    FREE_IF_NOT_NULL(base64_iv)

    return total_len;
} /* _secrets_encrypt_msg_and_base64 */

/*
 * Sets the encryption key, which is the user key xor'd with
 * the app key.
 */
void
_secrets_set_encryption_key(secrets_t * ctx, char * const buf) {
    int i = 0;

    for (; i < ctx->encryption_key_len; i++) {
        buf[i] = ctx->user_key[i] ^ ctx->app_key[i];
    }
}

/*
 * encrypts msg, returns newly alloc'd data in outbuf
 */
size_t
_secrets_encrypt_msg(secrets_t * ctx, char *msg, char **outbuf) {
    int    result        = 0;
    size_t bytes_written = 0;
    size_t msg_len       = 0;
    size_t num_blocks    = 0;
    char * ptr_cur_block = NULL;
    char   encryption_key[ctx->encryption_key_len];

    _secrets_set_encryption_key(ctx, encryption_key);

    if (msg == NULL) {
        return 0;
    }

    msg_len = strlen(msg) + 1;

    if (msg_len == 0) {
        return 0;
    }

    num_blocks    = 1 + (msg_len / ctx->block_len);
    ptr_cur_block = *outbuf = calloc(1, num_blocks * ctx->block_len);

    MCRYPT handle = ctx->handle;

    if (handle == MCRYPT_FAILED) {
        return 0;
    }

    result = mcrypt_generic_init(
        handle,
        encryption_key,
        ctx->encryption_key_len,
        ctx->iv);

    if (result < 0) {
        SECRETS_LOG("mcrypt_generic_init err")
        goto _encrypt_msg_err;
    }

    while (msg_len > 0) {
        memset(ctx->block, 0, ctx->block_len);
        memcpy(ctx->block, msg, msg_len);
        mcrypt_generic(handle, ctx->block, ctx->block_len);

        /* copy block to outbuf, then increment the block position */
        memcpy(ptr_cur_block, ctx->block, ctx->block_len);
        ptr_cur_block += ctx->block_len;
        bytes_written += ctx->block_len;

        msg_len        = (msg_len > ctx->block_len) ?  msg_len - ctx->block_len : 0;

        if (msg_len > 0) {
            msg += ctx->block_len;
        }
    }

    goto _encrypt_msg_ok;

_encrypt_msg_err:
    FREE_IF_NOT_NULL(*outbuf);
    bytes_written = 0;
_encrypt_msg_ok:

    mcrypt_generic_deinit(handle);
    /*   mcrypt_module_close(handle); */
    return bytes_written;
} /* _secrets_encrypt_msg */

/*
 * Generates a random string (e.g., for keys) of length `len` from
 * /dev/urandom, and writes to the location in `buf`.
 *
 * Returns the number of bytes written.
 */
int
_secrets_generate_random_string(char * buf, size_t len) {
    int           i = 0;
    unsigned char c;
    FILE        * urandom;

    urandom = fopen("/dev/urandom", "r");

    for (; i < len; i++) {
        c      = getc(urandom);
        buf[i] = c;
    }

    fclose(urandom);
    return len;
}

/*
 * Generates an iv of size `ctx->iv_len`
 */
int
secrets_generate_iv(secrets_t * ctx) {
    if (ctx->iv_len <= 0) {
        return 0;
    }

    return _secrets_generate_random_string(ctx->iv, ctx->iv_len);
}

int
secrets_generate_app_key(secrets_t * ctx) {
    if (ctx->encryption_key_len <= 0) {
        return 0;
    }

    return _secrets_generate_random_string(ctx->app_key, ctx->encryption_key_len);
}

int
secrets_generate_user_key(secrets_t * ctx) {
    if (ctx->encryption_key_len <= 0) {
        return 0;
    }

    return _secrets_generate_random_string(ctx->user_key, ctx->encryption_key_len);
}

char *
_secrets_base64_encode(char *buf, size_t len) {
    base64_encodestate encoder;
    int                bytes_written = 0;
    char             * outbuffer     = calloc(1, 2 * len + 1);

    base64_init_encodestate(&encoder);

    bytes_written = base64_encode_block(
        buf,
        len,
        outbuffer,
        &encoder);

    if (bytes_written > 0) {
        /*
         *  SECRETS_LOG("_secrets_get_base64_iv bytes written: %d\n", bytes_written) ;
         *   SECRETS_LOG("_secrets_get_base64_iv iv_len: %lu\n", len) ;
         */
        bytes_written += base64_encode_blockend(
            outbuffer + bytes_written,
            &encoder);
        /*
         *    SECRETS_LOG("_secrets_get_base64_iv bytes written: %d\n", bytes_written) ;
         * get rid of that nasty newline, i don't want it.
         */
        outbuffer[bytes_written - 1] = '\0';
        return outbuffer;
    }

    free(outbuffer);
    return NULL;
}

char *
_secrets_get_base64_iv(secrets_t * ctx) {
    return _secrets_base64_encode(ctx->iv, ctx->iv_len);
}

char *
_secrets_get_base64_app_key(secrets_t * ctx) {
    return _secrets_base64_encode(ctx->app_key, ctx->encryption_key_len);
}

char *
_secrets_get_base64_user_key(secrets_t * ctx) {
    return _secrets_base64_encode(ctx->user_key, ctx->encryption_key_len);
}

int
_secrets_base64_decode(char * buf_in, size_t buf_in_len, char * base64data,
                       size_t validate_bytes_decoded) {
    base64_decodestate decoder;
    int                bytes_written = 0;
    int                len           = strlen(base64data);

    if (len == 0) {
        return 0;           /* no bytes written */
    }

    char tmpbuf[len * 2];

    base64_init_decodestate(&decoder);
    memset(buf_in, 0, buf_in_len);
    memset(tmpbuf, 0, len * 2);

    bytes_written = base64_decode_block(
        base64data,
        len,
        tmpbuf,
        &decoder);


    if (bytes_written > 0) {
        if (buf_in_len < bytes_written) {
            SECRETS_LOG("[!] failure base64 decode - buffer size too small");
            return 0;
        }

        if (validate_bytes_decoded && bytes_written != buf_in_len) {
            /* a super bad error. */
            SECRETS_LOG("[!] failure in _secrets_base64_decode: %lu, bytes after %d", buf_in_len, bytes_written);
            return 0;
        }
        memcpy(buf_in, tmpbuf, bytes_written);
        return bytes_written;
    }

    return 0;
}

int
_secrets_load_base64_app_key(secrets_t * ctx, char * base64data) {
    return _secrets_base64_decode(ctx->app_key, ctx->encryption_key_len, base64data, 1);
}

int
_secrets_load_base64_user_key(secrets_t * ctx, char * base64data) {
    return _secrets_base64_decode(ctx->user_key, ctx->encryption_key_len, base64data, 1);
}

int
_secrets_load_base64_iv(secrets_t * ctx, char * base64data) {
    return _secrets_base64_decode(ctx->iv, ctx->iv_len, base64data, 1);
}

int
secrets_set_encrypted_env(secrets_t *ctx, const char * key, const char * val) {
    char * buf       = NULL;
    int    encrypted = 0;

    encrypted = secrets_encrypt_msg_and_base64(ctx, (char *)val, &buf);

    if (encrypted <= 0) {
        SECRETS_LOG("set_encrypted_env returned non value %d", encrypted);
        return 0;
    }

    ctx->glibc->glibc_setenv(key, buf, 1);

    SECRETS_LOG("setting %s=%s", key, buf);

    FREE_IF_NOT_NULL(buf);

    return encrypted;
}

secrets_t *
secrets_new(glibc_context_t * context) {
    secrets_t * ctx             = NULL;
    char      * base64_app_key  = NULL;
    char      * base64_user_key = NULL;
    int         loaded          = 0;
    int         test_mode       = 0;

    /* copy the context for local usage */
    ctx        = calloc(1, sizeof(secrets_t));
    ctx->glibc = context;


    if (!_secrets_crypt_initialize(ctx)) {
        ctx = NULL;
        goto _secrets_initialize_err;
    }

    if (test_mode) {
        secrets_generate_app_key(ctx);
        secrets_generate_user_key(ctx);
        secrets_generate_iv(ctx);

        base64_app_key  = _secrets_get_base64_app_key(ctx);
        SECRETS_LOG("app key is %s", base64_app_key)
        base64_user_key = _secrets_get_base64_user_key(ctx);
        SECRETS_LOG("user key is %s", base64_user_key)

        secrets_set_encrypted_env(ctx, "__SECRET_HELLO", "this is a test val");
        secrets_set_encrypted_env(ctx, "__SECRET_GOODBYE", "this is goodbye");

    } else {
        if (!(base64_app_key = _secrets_lookup_app_key(ctx)) ||
            strlen(base64_app_key) == 0) {
            /* no key found */
            SECRETS_LOG("No app key found");
            goto _secrets_initialize_err;
        }

        if (!(base64_user_key = _secrets_lookup_user_key(ctx)) ||
            strlen(base64_user_key) == 0) {
            /* no key found */
            SECRETS_LOG("No user key found");
            goto _secrets_initialize_err;
        }
    }


    loaded = _secrets_load_base64_user_key(ctx, base64_user_key);

    if (!loaded) {
        SECRETS_LOG("No user key loaded");
        goto _secrets_initialize_err;
    }

    loaded = _secrets_load_base64_app_key(ctx, base64_app_key);

    if (!loaded) {
        SECRETS_LOG("No app key loaded");
        goto _secrets_initialize_err;
    }

    secrets_set_secrets(ctx, __environ);

    goto _secrets_initialize_done;

_secrets_initialize_err:
    if (ctx) {
        secrets_free(ctx);
        ctx = NULL;
    }

_secrets_initialize_done:
    FREE_IF_NOT_NULL(base64_user_key);
    FREE_IF_NOT_NULL(base64_app_key);
    return ctx;
};

/*
 * TODO: set secrets
 */
void
secrets_set_secrets(secrets_t * ctx, const char **environ) {
    char * secret_keys[MAX_SECRETS];
    int    count = 0;
    int    i     = 0;

    if (environ == NULL) {
        return;
    }

    count = secrets_find_all_secret_keys(environ, secret_keys, MAX_SECRETS);

    if (count == 0) {
        return;
    }

    for (i = 0; i < count; i++) {
        const char * key    = secret_keys[i] + ENV_PREFIX_LEN;
        size_t       keylen = strlen(key);
        const char * val    = ctx->glibc->glibc_getenv(secret_keys[i]);
        char       * out    = NULL;
        if (_secrets_decrypt_base64_msg_and_iv(ctx, (char *)val, &out)) {
            ctx->glibc->glibc_setenv(key, out, 1);
        } else {
            SECRETS_LOG("nothing returned")
        }
        FREE_IF_NOT_NULL(out);
    }

    return;
}

/*
 * TODO: unset secrets
 *
 * Note: a maximum of 1024 secrets can be 'unset'.
 */
char **
secrets_unset_secrets(const char **environ) {
    char * keys_to_unset[MAX_SECRETS];
    int    num_keys_to_unset = 0;
    int    i = 0;

    if (environ == NULL) {
        return NULL;
    }

    num_keys_to_unset = secrets_find_all_secret_keys(environ, keys_to_unset, MAX_SECRETS);

    if (num_keys_to_unset > 0) {
        for (i = 0; i < num_keys_to_unset; i++) {
            const char * key    = keys_to_unset[i] + ENV_PREFIX_LEN;
            size_t       keylen = strlen(key);
            const char **ptr    = environ;

            while (*ptr) {
                char  *cur = (char *)*ptr;
                size_t len = strlen(cur);

                if (len >= (keylen + 2)) {
                    if (strncmp(cur, key, keylen) == 0 && cur[keylen] == '=') {
                        cur[keylen + 1] = ' ';
                        cur[keylen + 2] = '\0';
                    }
                }
                ptr++;
            }
        }

        /* free the keys */
        for (i = 0; i < num_keys_to_unset; i++) {
            FREE_IF_NOT_NULL(keys_to_unset[i]);
        }
    }

    return (char **)environ;
}     /* secrets_unset_secrets */

int
secrets_find_all_secret_keys(const char **environ, char *keysbuf[], size_t bufsize) {
    const char **ptr = NULL;
    int          idx = 0;

    memset(keysbuf, 0, bufsize);

    if (environ == NULL) {
        return 0;
    }

    ptr = environ;

    while (ptr != NULL && *ptr && idx < bufsize) {
        const char *cur = *ptr;

        if (strncmp(cur, ENV_PREFIX, ENV_PREFIX_LEN) == 0) {
            size_t len = strlen(cur);
            SECRETS_LOG("found secret key %s", cur);
            char  *key = (char *)malloc(len);     /* it won't have the equal sign, so len is ok */
            char   val[1];                        /* we don't really care about the val so just ignore here. */
            int    err = secrets_parse_key_eq_val(cur, key, len, val, sizeof(val));


            if (!err) {
                keysbuf[idx] = key;
                idx++;
            } else {
                FREE_IF_NOT_NULL(key);
            }
        }
        ptr++;
    }
    return idx;
}

int
secrets_unset_non_secret_key(const char *secret_key) {
    size_t len;
    char * non_secret_key;

    if (!secret_key) {
        return 0;
    }

    len = strlen(secret_key);

    if (len <= ENV_PREFIX_LEN) {
        return 0;
    }

    non_secret_key = (char *)secret_key + ENV_PREFIX_LEN;

    if (!*non_secret_key) {
        /* it's null, just return; */
        return 0;
    }
}

/*
 * parse the key=value from a string
 */
int
secrets_parse_key_eq_val(const char * str, char *keybuf, size_t keylen, char *valbuf, size_t vallen) {
    return _secrets_parse_key_eq_val('=', str, keybuf, keylen, valbuf, vallen);
}

int
_secrets_parse_key_eq_val
(
    char         delim_char,
    const char * str,
    char        *keybuf,
    size_t       keylen,
    char        *valbuf,
    size_t       vallen) {
    size_t      cur_key_len      = 0;
    size_t      cur_val_len      = 0;
    int         delim_char_found = 0;
    const char *orig = str;

    if (!str || vallen <= 0 || keylen <= 0) {
        return -1;
    }

    /* first, get the key. */
    while (*str) {
        char c = *str;
        str++;
        if (c == delim_char) {
            delim_char_found = 1;
            break;
        } else {
            if (cur_key_len < (keylen - 1)) {
                *keybuf++ = c;
                cur_key_len++;
            }
        }
    }

    if (!delim_char_found) {
        SECRETS_LOG("failed to parse: %s, no delim char %c found", orig, delim_char)
        return -1;
    }

    if (keylen > 0) {
        *keybuf = '\0';
    }

    /* first, get the key. */
    while (*str) {
        char c = *str;
        str++;
        if (c == '\0') {
            break;
        } else {
            if (cur_val_len < (vallen - 1)) {
                *valbuf++ = c;
                cur_val_len++;
            }
        }
    }

    if (vallen > 0) {
        *valbuf = '\0';
    }

    return 0;
}     /* secrets_parse_key_eq_val */

void
secrets_print_environ(const char **environ) {
    const char **ptr = NULL;

    if (environ == NULL) {
        return;
    }

    ptr = environ;

    while (ptr != NULL && *ptr) {
        ptr++;
    }
}

char *
secrets_get_secure_name(const char *name) {
    char  *str;
    size_t len      = 0;
    size_t name_len = 0;

    if (!name) {
        return NULL;
    }

    name_len = strlen(name);
    len      = name_len + ENV_PREFIX_LEN + 1;

    if (len < name_len) {
        return NULL;
    }

    str = malloc(len);

    snprintf(str, len, "SECRET_%s", name);

    return str;
}

