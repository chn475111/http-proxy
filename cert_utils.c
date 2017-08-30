#define _GNU_SOURCE
#include <string.h>
#include "file_utils.h"
#include "cert_utils.h"

int get_format_from_file(char *filename)
{
    int ret = 0;
    int filesize = 0;
    char *file = NULL;

    if(filename == NULL)
        return -1;

    ret = file_mmap(filename, &file, &filesize);
    if(ret != 0)
        return -1;

    if(strcasestr(file, "-----") != NULL || file[0] != 0x30)
    {
        file_munmap(file, filesize);
        return SSL_FILETYPE_PEM;        //pem编码
    }
    else
    {
        file_munmap(file, filesize);
        return SSL_FILETYPE_ASN1;       //der编码
    }
}

X509* get_x509_from_file(char *filename)
{
    BIO *bio = NULL;
    X509 *x509 = NULL;

    bio = BIO_new_file(filename, "rb");
    if(bio == NULL)
        return NULL;

    if(get_format_from_file(filename) == SSL_FILETYPE_ASN1)
        x509 = d2i_X509_bio(bio, NULL);
    else
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    if(bio) BIO_free_all(bio);
    return x509;
}

EVP_PKEY* get_pubkey_from_file(char *filename)
{
    BIO *bio = NULL;
    EVP_PKEY *pubkey = NULL;

    bio = BIO_new_file(filename, "rb");
    if(bio == NULL)
        return NULL;

    if(get_format_from_file(filename) == SSL_FILETYPE_ASN1)
        pubkey = d2i_PUBKEY_bio(bio, NULL);
    else
        pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    if(bio) BIO_free_all(bio);
    return pubkey;
}

EVP_PKEY* get_prvkey_from_file(char *filename, char *passwd)
{
    BIO *bio = NULL;
    EVP_PKEY *prvkey = NULL;

    bio = BIO_new_file(filename, "rb");
    if(bio == NULL)
        return NULL;

    if(get_format_from_file(filename) == SSL_FILETYPE_ASN1)
    {
        if(passwd == NULL || strlen(passwd) == 0)
            prvkey = d2i_PrivateKey_bio(bio, NULL);
        else
            prvkey = d2i_PKCS8PrivateKey_bio(bio, NULL, NULL, (void*)passwd);
    }
    else
        prvkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*)passwd);

    if(bio) BIO_free_all(bio);
    return prvkey;
}
