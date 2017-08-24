#ifndef __SSL_UTILS_H__
#define __SSL_UTILS_H__

#include <openssl/err.h>
#include <openssl/ssl.h>

int ssl_accept(SSL *ssl);

int ssl_connect(SSL *ssl);

int ssl_read(SSL *ssl, char *buf, int len);

int ssl_write(SSL *ssl, char *buf, int len);

#endif
