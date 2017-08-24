#include <sys/types.h>
#include <unistd.h>
#include "utils.h"
#include "file_utils.h"
#include "cert_utils.h"
#include "crypto_lock.h"
#include "event_handler.h"
#include "log.h"
#include "base64.h"
#include "passwd.h"
#include "signals.h"
#include "worker.h"
#include "master.h"

static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    int error = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    switch (error)
    {
        case X509_V_OK:
            break;
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            log_debug("depth = %d, error = %d, %s", depth, error, X509_verify_cert_error_string(error));
            X509_STORE_CTX_set_error(ctx, X509_V_OK);
            ok = 1;
            break;
        default:
            log_err("depth = %d, error = %d, %s", depth, error, X509_verify_cert_error_string(error));
            break;
    }
    return ok;
}

SSL_CTX *ssl_ctx_init(char *ca, char *crl, char *cert, char *key, \
    char *enccert, char *enckey, char *sigcert, char *sigkey, char *passwd, char *cipher, int verify)
{
    SSL_CTX *ctx = NULL;
    SSL_METHOD *meth = NULL;

    int nid = 0;
    EC_KEY *ecdh = NULL;

    int mode = SSL_VERIFY_NONE;

    meth = (SSL_METHOD*)SSLv23_server_method();
    ctx = SSL_CTX_new(meth);
    if(!ctx)
    {
        log_err("SSL_CTX_new failed");
        return NULL;
    }

    if(cipher) SSL_CTX_set_cipher_list(ctx, cipher);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
//  SSL_CTX_set_timeout(ctx, 7200L);

    nid = OBJ_sn2nid((const char *)"secp384r1");
    if(nid == 0)
    {
        log_err("OBJ_sn2nid failed");
        goto ErrP;
    }
    ecdh = EC_KEY_new_by_curve_name(nid);
    if(ecdh == NULL)
    {
        log_err("EC_KEY_new_by_curve_name failed");
        goto ErrP;
    }
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);

#if 0
    SSL_CTX_set_verify_depth()
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    "level 0:peer certificate", "level 1: CA certificate", "level 2: higher level CA certificate"
#endif

#if 0
    SSL_CTX_load_verify_locations()
    -----BEGIN CERTIFICATE-----
    ... (CA certificate in base64 encoding) ...
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    ... (CA certificate in base64 encoding) ...
    -----END CERTIFICATE-----
#endif

//  SSL_CTX_set_verify_depth(ctx, 9);
    switch(verify)
    {
        case 0:         //单向认证(默认)
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

    if(is_file_exist(crl))
    {
        if(SSL_CTX_use_crl_file_ext(ctx, crl, get_format_from_file(crl)) != 1)
        {
            log_err("SSL_CTX_use_crl_file_ext failed");
            goto ErrP;
        }
    }

#if 1
    int length = 65536;
    unsigned char password[65536] = {0};
    length = passwd_decrypt((unsigned char*)passwd, passwd ? strlen(passwd) : 0, password, length);
    if(length <= 0)
    {
        log_err("passwd decrypt failed - %s", passwd);
        goto ErrP;
    }
    log_debug("passwd decrypt succeed - %s", password);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)password);
#else
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)passwd);
#endif

    if(is_file_exist(cert) && is_file_exist(key))
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

    if(is_file_exist(enccert) && is_file_exist(sigcert) && is_file_exist(enckey) && is_file_exist(sigkey))
    {
        if(SSL_CTX_use_certificate_file_ext(ctx, enccert, sigcert, get_format_from_file(enccert)) != 1)
        {
            log_err("SSL_CTX_use_certificate_file_ext failed");
            goto ErrP;
        }
        if(SSL_CTX_use_PrivateKey_file_ext(ctx, enckey, sigkey, get_format_from_file(enckey)) != 1)
        {
            log_err("SSL_CTX_use_PrivateKey_file_ext failed");
            goto ErrP;
        }
        if(SSL_CTX_check_private_key_ext(ctx) != 1)
        {
            log_err("SSL_CTX_check_private_key_ext failed");
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
    int loop = 0;
    config_t *conf = NULL;
    master_t *mast = (master_t*)data;

    struct event ev_sigint;
    struct event ev_sigterm;

    struct timeval tv = 
    {
        .tv_sec = 1,
        .tv_usec = 0
    };

    if(mast == NULL)
        exit(EXIT_FAILURE);
    conf = &mast->conf;

    SSL_library_init();
    SSL_load_error_strings();

    OpenSSL_add_all_algorithms();

#if 1
    ret = set_proc_priority(0);
    if(ret == -1)
    {
        log_err("set priority failed - %d: %s", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }

    ret = set_proc_affinity(getpid()%get_proc_num());
    if(ret == -1)
    {
        log_err("set affinity failed - %d: %s", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
#endif

    worker_t *work = (worker_t*)malloc(sizeof(worker_t));
    if(work == NULL)
    {
        log_err("malloc memory from OS failed - %d: %s", errno, strerror(errno));
        goto ErrP;
    }
    memset(work, 0, sizeof(worker_t));

    work->mast = mast;
    work->base = event_base_new();
    if(work->base == NULL)
    {
        log_err("event_base_new failed - %d: %s", errno, strerror(errno));
        goto ErrP;
    }

    //结束信号
    evsignal_assign(&ev_sigint, work->base, SIGINT, on_signal, (void*)&ev_sigint);
    evsignal_add(&ev_sigint, NULL);
    evsignal_assign(&ev_sigterm, work->base, SIGTERM, on_signal, (void*)&ev_sigterm);
    evsignal_add(&ev_sigterm, NULL);

    //计时器
    evtimer_assign(&work->ev_timer, work->base, on_timer, (void*)work);
    evtimer_add(&work->ev_timer, &tv);

    for(loop = 0; loop < conf->count; loop ++)
    {
        if(conf->ctrl[loop].isEnable)
        {
            //SSL_CTX
            work->ctx[loop] = ssl_ctx_init( is_file_exist(conf->ssl[loop].ca) ? conf->ssl[loop].ca : conf->ca,              \
                                            is_file_exist(conf->ssl[loop].crl) ? conf->ssl[loop].crl : conf->crl,           \
                                            conf->ssl[loop].cert, conf->ssl[loop].key,                                      \
                                            conf->ssl[loop].enccert, conf->ssl[loop].enckey,                                \
                                            conf->ssl[loop].sigcert, conf->ssl[loop].sigkey,                                \
                                            conf->ssl[loop].passwd, conf->ssl[loop].cipher, conf->ssl[loop].isVerify );
            if(work->ctx[loop] == NULL)
            {
                log_err("ssl ctx init server%d failed - %d: %s", loop, errno, strerror(errno) );
                goto ErrP;
            }

            //FD
            work->conn[mast->fd[loop]].slot = loop;
            work->conn[mast->fd[loop]].fd = mast->fd[loop];
            work->conn[mast->fd[loop]].ssl = NULL;
            work->conn[mast->fd[loop]].ip = NULL;
            work->conn[mast->fd[loop]].port = 0;
            work->conn[mast->fd[loop]].http = NULL;
            work->conn[mast->fd[loop]].peer = NULL;

            event_assign(&work->conn[mast->fd[loop]].event, work->base, mast->fd[loop], EV_READ|EV_PERSIST, tcp_accept_from_frontend, (void*)work);
            event_add(&work->conn[mast->fd[loop]].event, NULL);
        }
    }

    pthread_setup();
    timer_init(&work->timer);
    INIT_LIST_HEAD(&work->list);

    signals_register();
    event_base_dispatch(work->base);        //main loop

    event_del(&ev_sigint);
    event_del(&ev_sigterm);
    if(work)
    {
        for(loop = 0; loop < MAX_CONN_NUM; loop ++)
            event_conn_free(work, &work->conn[loop]);
        for(loop = 0; loop < MAX_COUNT_NUM; loop ++)
            ssl_ctx_exit(work->ctx[loop]);
        INIT_LIST_HEAD(&work->list);
        timer_exit(&work->timer);
        event_del(&work->ev_timer);
        event_base_free(work->base);
        free(work);
    }
    if(mast)
    {
        config_free((void*)&mast->conf);
        free(mast);
    }
    pthread_cleanup();
    log_close();
    exit(EXIT_SUCCESS);
ErrP:
    event_del(&ev_sigint);
    event_del(&ev_sigterm);
    if(work)
    {
        for(loop = 0; loop < MAX_CONN_NUM; loop ++)
            event_conn_free(work, &work->conn[loop]);
        for(loop = 0; loop < MAX_COUNT_NUM; loop ++)
            ssl_ctx_exit(work->ctx[loop]);
        INIT_LIST_HEAD(&work->list);
        timer_exit(&work->timer);
        event_del(&work->ev_timer);
        event_base_free(work->base);
        free(work);
    }
    if(mast)
    {
        config_free((void*)&mast->conf);
        free(mast);
    }
    pthread_cleanup();
    log_close();
    exit(EXIT_FAILURE);
}
