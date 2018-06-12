#include <pthread.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "crypto_lock.h"

static pthread_mutex_t *lock_cs = NULL;

static unsigned long pthread_id_cb(void)
{
    return (unsigned long)pthread_self();
}

static void pthread_locking_cb(int mode, int type, const char *file, int line)
{
    if(mode & CRYPTO_LOCK)
        pthread_mutex_lock(&lock_cs[type]);
    else
        pthread_mutex_unlock(&lock_cs[type]);
}

void pthread_setup(void)
{
    int i = 0;

    lock_cs = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
    for(i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(&lock_cs[i], NULL);

    CRYPTO_set_id_callback(pthread_id_cb);
    CRYPTO_set_locking_callback(pthread_locking_cb);
}

void pthread_cleanup(void)
{
    int i = 0;

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    for(i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&lock_cs[i]);
    if(lock_cs)
    {
        OPENSSL_free(lock_cs);
        lock_cs = NULL;
    }
}
