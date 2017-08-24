#include <pthread.h>
#include <openssl/ssl.h>
#include "crypto_lock.h"

static pthread_mutex_t *crypto_lock = NULL;

static pthread_t pthread_id_cb()
{
    return pthread_self();
}

static void pthread_locking_cb(int mode, int n, const char *file, int line)
{
    if(mode & CRYPTO_LOCK)
        pthread_mutex_lock(&crypto_lock[n]);
    else
        pthread_mutex_unlock(&crypto_lock[n]);
}

int pthread_setup()
{
    int loop = 0;
    crypto_lock = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
    if(!crypto_lock)
        return 0;
    for(loop = 0; loop < CRYPTO_num_locks(); loop ++)
        pthread_mutex_init(&crypto_lock[loop], NULL);
    CRYPTO_set_id_callback(pthread_id_cb);
    CRYPTO_set_locking_callback(pthread_locking_cb);
    return 1;
}

int pthread_cleanup()
{
    int loop = 0;
    if(!crypto_lock)
        return 0;
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for(loop = 0; loop < CRYPTO_num_locks(); loop ++)
        pthread_mutex_destroy(&crypto_lock[loop]);
    OPENSSL_free(crypto_lock);
    crypto_lock = NULL;
    return 1;
}
