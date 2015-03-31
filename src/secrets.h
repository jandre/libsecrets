#ifndef _SECRETS_H_
#define _SECRETS_H_

#include <stdio.h>
#include <stdlib.h>
#include <mcrypt.h>
#include <keyutils.h>

typedef struct {
    void *glibc;
    char  * (*glibc_getenv)(const char *);
    int (*glibc_setenv)(const char *, const char *, int);
    int (*glibc_unsetenv)(const char *);
    int (*glibc_execve)(const char *filename, char *const argv[], char *const envp[]);
    ssize_t (*glibc_readlink)(const char *path, char *buf, size_t bufsize);
} glibc_context_t;


/* key that holds the encrypted encryption key for env variables. */
#define SECRETS_ENV_KEY              "__SECRETS_APP_KEY"
#define SECRETS_KEYRING_ENV_KEY      "__SECRETS_USER_KEY_ID"
#define SECRETS_KEYRING_DEFAULT_DESC "__SECRETS_USER_KEY"
#define ENV_PREFIX                   "__SECRET_"
#define ENV_PREFIX_LEN               9


typedef struct {
    glibc_context_t *glibc;

    size_t encryption_key_len;

    char *user_key;   /* user key is the key provided by the keying */
    char *app_key;    /* app key is the key provided by the __SECRETS_APP_KEY variable */

    char  *iv;
    size_t iv_len;
    char  *block;
    size_t block_len;

    MCRYPT handle;
} secrets_t;

secrets_t * secrets_new(glibc_context_t *);
void        secrets_free(secrets_t *);

int         secrets_set_encrypted_env(secrets_t *, const char *, const char *);

char      * secrets_get_secure_name(const char *);
void        secrets_print_environ(const char **);
char     ** secrets_unset_secrets(const char **);
void        secrets_set_secrets(secrets_t *, const char **);
int         secrets_parse_key_eq_val(const char *, char *, size_t, char *, size_t);
int         secrets_find_all_secret_keys(const char **, char *[], size_t );

int         secrets_generate_app_key(secrets_t *);
int         secrets_generate_user_key(secrets_t *);
int         secrets_generate_iv(secrets_t *);
size_t      secrets_encrypt_msg_and_base64(secrets_t *, char *, char **);

#endif
