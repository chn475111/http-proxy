#include "log.h"
#include "ssl_utils.h"

static const char *ssl_handshake_error[] = {
    [SSL_ERROR_NONE]                = "SSL_ERROR_NONE",
    [SSL_ERROR_SSL]                 = "SSL_ERROR_SSL",
    [SSL_ERROR_WANT_READ]           = "SSL_ERROR_WANT_READ",
    [SSL_ERROR_WANT_WRITE]          = "SSL_ERROR_WANT_WRITE",
    [SSL_ERROR_WANT_X509_LOOKUP]    = "SSL_ERROR_WANT_X509_LOOKUP",
    [SSL_ERROR_SYSCALL]             = "SSL_ERROR_SYSCALL",
    [SSL_ERROR_ZERO_RETURN]         = "SSL_ERROR_ZERO_RETURN",
    [SSL_ERROR_WANT_CONNECT]        = "SSL_ERROR_WANT_CONNECT",
    [SSL_ERROR_WANT_ACCEPT]         = "SSL_ERROR_WANT_ACCEPT"
};

const char* ssl_get_error(int code)
{
    return ssl_handshake_error[code];
}

int ssl_accept(SSL *ssl)
{
    int ret = 0;

    if(ssl == NULL)
        return -9;

    if(SSL_is_init_finished(ssl) == false)
    {
        do{
            ret = SSL_accept(ssl);
            if(ret > 0                                                   \
                ||(SSL_get_error(ssl, ret) != SSL_ERROR_WANT_READ        \
                && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_WRITE       \
                && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_X509_LOOKUP \
                && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_CONNECT     \
                && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_ACCEPT))
                break;
        }while(0);

        if(ret <= 0)
        {
            ERR_print_errors_fp(stderr);
            switch(SSL_get_error(ssl, ret))
            {
                case SSL_ERROR_NONE:
                    break;          //握手成功
                case SSL_ERROR_WANT_READ: case SSL_ERROR_WANT_WRITE: case SSL_ERROR_WANT_X509_LOOKUP:
                case SSL_ERROR_WANT_CONNECT: case SSL_ERROR_WANT_ACCEPT:
                    log_warning("SSL_accept failed - %lu, %d, %s", ERR_get_error(), SSL_get_error(ssl, ret), ssl_get_error(SSL_get_error(ssl, ret)));
                    return 0;       //尚未握手成功
                case SSL_ERROR_SSL: case SSL_ERROR_SYSCALL: case SSL_ERROR_ZERO_RETURN:
                    log_err("SSL_accept failed - %lu, %d, %s", ERR_get_error(), SSL_get_error(ssl, ret), ssl_get_error(SSL_get_error(ssl, ret)));
                    return -1;      //握手失败
            }
        }
    }

    return 1;
}

int ssl_connect(SSL *ssl)
{
    int ret = 0;

    if(ssl == NULL)
        return -9;

    if(SSL_is_init_finished(ssl) == false)
    {
        do{
            ret = SSL_connect(ssl);
            if(ret > 0                                                   \
                ||(SSL_get_error(ssl, ret) != SSL_ERROR_WANT_READ        \
                && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_WRITE       \
                && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_X509_LOOKUP \
                && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_CONNECT     \
                && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_ACCEPT))
                break;
        }while(0);

        if(ret <= 0)
        {
            ERR_print_errors_fp(stderr);
            switch(SSL_get_error(ssl, ret))
            {
                case SSL_ERROR_NONE:
                    break;          //握手成功
                case SSL_ERROR_WANT_READ: case SSL_ERROR_WANT_WRITE: case SSL_ERROR_WANT_X509_LOOKUP:
                case SSL_ERROR_WANT_CONNECT: case SSL_ERROR_WANT_ACCEPT:
                    log_warning("SSL_connect failed - %lu, %d, %s", ERR_get_error(), SSL_get_error(ssl, ret), ssl_get_error(SSL_get_error(ssl, ret)));
                    return 0;       //尚未握手成功
                case SSL_ERROR_SSL: case SSL_ERROR_SYSCALL: case SSL_ERROR_ZERO_RETURN:
                    log_err("SSL_connect failed - %lu, %d, %s", ERR_get_error(), SSL_get_error(ssl, ret), ssl_get_error(SSL_get_error(ssl, ret)));
                    return -1;      //握手失败
            }
        }
    }

    return 1;
}

int ssl_read(SSL *ssl, char *buf, int len)
{
    int ret = 0;
    int read_len = 0;

    if(ssl == NULL)
        return -9;

    do{
        ret = SSL_read(ssl, buf+read_len, len-read_len);
        if(ret <= 0)
        {
            ERR_print_errors_fp(stderr);
            switch(SSL_get_error(ssl, ret))
            {
                case SSL_ERROR_NONE:
                    break;          //读成功
                case SSL_ERROR_WANT_READ: case SSL_ERROR_WANT_WRITE: case SSL_ERROR_WANT_X509_LOOKUP:
                case SSL_ERROR_WANT_CONNECT: case SSL_ERROR_WANT_ACCEPT:
                    break;          //尚未读成功
                case SSL_ERROR_ZERO_RETURN:
                    return 0;       //对端关闭连接
                case SSL_ERROR_SSL: case SSL_ERROR_SYSCALL:
                    log_err("SSL_read failed - %lu, %d, %s", ERR_get_error(), SSL_get_error(ssl, ret), ssl_get_error(SSL_get_error(ssl, ret)));
                    return -1;      //读失败
            }
        }
        read_len += ret;
    }while(0);

    return read_len;
}

int ssl_write(SSL *ssl, char *buf, int len)
{
    int ret = 0;
    int write_len = 0;

    if(ssl == NULL)
        return -9;

    do{
        ret = SSL_write(ssl, buf+write_len, len-write_len);
        if(ret <= 0)
        {
            ERR_print_errors_fp(stderr);
            switch(SSL_get_error(ssl, ret))
            {
                case SSL_ERROR_NONE:
                    break;          //写成功
                case SSL_ERROR_WANT_READ: case SSL_ERROR_WANT_WRITE: case SSL_ERROR_WANT_X509_LOOKUP:
                case SSL_ERROR_WANT_CONNECT: case SSL_ERROR_WANT_ACCEPT:
                    break;          //尚未写成功
                case SSL_ERROR_ZERO_RETURN:
                    return 0;       //对端关闭连接
                case SSL_ERROR_SSL: case SSL_ERROR_SYSCALL:
                    log_err("SSL_write failed - %lu, %d, %s", ERR_get_error(), SSL_get_error(ssl, ret), ssl_get_error(SSL_get_error(ssl, ret)));
                    return -1;      //写失败
            }
        }
        write_len += ret;
    }while(0);

    return write_len;
}
