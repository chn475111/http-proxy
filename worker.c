#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include "log.h"
#include "utils.h"
#include "signals.h"
#include "file_utils.h"
#include "cert_utils.h"
#include "fd_utils.h"
#include "tcp_utils.h"
#include "crypto_lock.h"
#include "setproctitle.h"
#include "event_handler.h"
#include "worker.h"
#include "master.h"

void on_stop(int fd, short events, void *data)
{
    struct event_base *base = (struct event_base*)data;
    struct timeval tv = 
    {
        .tv_sec = 1,
        .tv_usec = 0
    };
    event_base_loopexit(base, &tv);

    log_info("proxy was on stop");
}

void on_timer(int fd, short events, void *data)
{
    worker_t *work = (worker_t*)data;
    struct timeval tv = 
    {
        .tv_sec = 30,
        .tv_usec = 0
    };
    evtimer_add(&work->timer, &tv);

    log_debug("proxy was on timer");
}

static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    int error = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    const char *error_string = X509_verify_cert_error_string(error);
    switch(error)
    {
        case X509_V_OK:
            break;
        default:
            log_err("depth = %d, error = %d - %s", depth, error, error_string);
            break;
    }
    return ok;
}

SSL_CTX *ssl_ctx_init(char *ca, char *cert, char *key, char *passwd, char *cipher, int verify)
{
    SSL_CTX *ctx = NULL;
    int mode = SSL_VERIFY_NONE;

    ctx = SSL_CTX_new(SSLv23_server_method());
    if(!ctx)
    {
        log_err("SSL_CTX_new failed");
        return NULL;
    }
    if(cipher) SSL_CTX_set_cipher_list(ctx, cipher);

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_set1_curves_list(ctx, "prime256v1:secp384r1");

    switch(verify)
    {
        case 0:         //单向认证
            mode = SSL_VERIFY_NONE;
            break;
        case 1:         //双向认证
            mode = SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            break;
        default:
            log_warning("unknown verify type: %d", verify);
            break;
    }
    SSL_CTX_set_verify(ctx, mode, verify_callback);

    if(verify)
    {
        if(SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1)
        {
            log_err("SSL_CTX_load_verify_locations failed");
            goto ErrP;
        }
        SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca));
    }

    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)passwd);
    if(is_file_exist(cert) || is_file_exist(key))
    {
        if(SSL_CTX_use_certificate_file(ctx, cert, get_format_from_file(cert)) != 1)
        {
            log_err("SSL_CTX_use_certificate_file failed");
            goto ErrP;
        }
        if(SSL_CTX_use_PrivateKey_file(ctx, key, get_format_from_file(key)) != 1)
        {
            log_err("SSL_CTX_use_PrivateKey_file failed");
            goto ErrP;
        }
        if(SSL_CTX_check_private_key(ctx) != 1)
        {
            log_err("SSL_CTX_check_private_key failed");
            goto ErrP;
        }
    }

    return ctx;
ErrP:
    ERR_print_errors_fp(stderr);
    ssl_ctx_exit(ctx);
    return NULL;
}

void ssl_ctx_exit(SSL_CTX *ctx)
{
    if(ctx) SSL_CTX_free(ctx);
}

void service_worker_process(void *data)
{
    int ret = 0;
    int i = 0;
    char *env = NULL;
    struct event stop;

    if(data == NULL)
    {
        log_crit("worker internal error - %p", data);
        exit(EXIT_FAILURE);
    }

    worker_t *work = (worker_t*)data;
    master_t *mast = work->mast;
    proxy_t *proxy = &mast->proxy;

    struct timeval tv = 
    {
        .tv_sec = 30,
        .tv_usec = 0
    };

    work->pid = getpid();
    fd_close(work->sockfd[0]);

#if 1
    ret = set_proc_priority(0);
    if(ret < 0)
    {
        log_err("set priority failed - %d: %s", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }

    ret = set_proc_affinity(getpid()%get_proc_num());
    if(ret < 0)
    {
        log_err("set affinity failed - %d: %s", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
#endif

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    pthread_setup();
    for(i = 0; i < proxy->serverNumber; i++)
    {
        cred_t *cred = proxy->serverArray[i].cred;
        work->ctx[i] = ssl_ctx_init(cred->ca, cred->cert, cred->key, cred->passwd, cred->cipher, cred->verify);
        if(work->ctx[i] == NULL)
        {
            log_err("ssl ctx init \"%s\" failed - %d: %s", cred->name, errno, strerror(errno));
            goto ErrP;
        }
    }

    work->base = event_base_new();
    if(work->base == NULL)
    {
        log_err("event_base_new failed - %d: %s", errno, strerror(errno));
        goto ErrP;
    }
    env = os_setproctitle(os_argc, os_argv, "proxy: worker process");

    evsignal_assign(&stop, work->base, SIGINT, on_stop, (void*)work->base);
    evsignal_add(&stop, NULL);

    evtimer_assign(&work->timer, work->base, on_timer, (void*)work);
    evtimer_add(&work->timer, &tv);

    for(i = 0; i < proxy->serverNumber; i++)
    {
        int fd = mast->fd[i];
        if(fd > 0)
        {
            work->conn[fd].slot = i;
            work->conn[fd].fd = fd;

            event_assign(&work->conn[fd].event, work->base, fd, EV_READ|EV_PERSIST, tcp_accept_from_frontend, (void*)work);
            event_add(&work->conn[fd].event, NULL);
        }
    }

    signals_register();
    event_base_dispatch(work->base);

    evsignal_del(&stop);
    if(work)
    {
        evtimer_del(&work->timer);
        fd_close(work->sockfd[1]);
        for(i = 0; i < MAX_CONN_NUM; i++) tcp_conn_free(&work->conn[i]);
        if(work->base) event_base_free(work->base);
    }
    if(proxy)
    {
        for(i = 0; i < proxy->serverNumber; i++) ssl_ctx_exit(work->ctx[i]);
        cfg_exit(proxy);
    }
    if(mast)
    {

        if(mast->workArray) free(mast->workArray);
        free(mast);
    }
    if(env) free(env);
    pthread_cleanup();
    log_close();
    exit(EXIT_SUCCESS);
ErrP:
    if(work)
    {
        fd_close(work->sockfd[1]);
        for(i = 0; i < MAX_CONN_NUM; i++) tcp_conn_free(&work->conn[i]);
        if(work->base) event_base_free(work->base);
    }
    if(proxy)
    {
        for(i = 0; i < proxy->serverNumber; i++) ssl_ctx_exit(work->ctx[i]);
        cfg_exit(proxy);
    }
    if(mast)
    {
        if(mast->workArray) free(mast->workArray);
        free(mast);
    }
    if(env) free(env);
    pthread_cleanup();
    log_close();
    exit(EXIT_FAILURE);
    return;
}
