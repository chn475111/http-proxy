#ifndef __CERT_UTILS_H__
#define __CERT_UTILS_H__

#include <openssl/err.h>
#include <openssl/ssl.h>

int get_format_from_file(char *filename);

X509* get_x509_from_file(char *filename);

EVP_PKEY* get_pubkey_from_file(char *filename);

EVP_PKEY* get_prvkey_from_file(char *filename, char *passwd);

#endif
