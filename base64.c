#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "base64.h"

int base64encode(const unsigned char *input, int input_length, unsigned char *output, int output_length)
{
	int len = 0;
	char *buf = NULL;
	BIO *b64 = NULL;
	BIO *bio = NULL;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	if(b64 == NULL || bio == NULL)
		return 0;

	b64 = BIO_push(b64, bio);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	len = BIO_write(b64, (void*)input, input_length);
	if(b64 == NULL || len <= 0)
		return 0;
	(void)BIO_flush(b64);

	len = (int)BIO_get_mem_data(b64, &buf);
	if(len <= 0 || buf == NULL)
		return 0;
	memcpy(output, buf, len < output_length ? len : output_length);

	if(b64) BIO_free_all(b64);
	return len < output_length ? len : output_length;
}

int base64decode(const unsigned char *input, int input_length, unsigned char *output, int output_length)
{
	int len = 0;
	BIO *b64 = NULL;
	BIO *bio = NULL;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_mem_buf((void*)input, input_length);
	if(b64 == NULL || bio == NULL)
		return 0;

	b64 = BIO_push(b64, bio);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	len = BIO_read(b64, (void*)output, output_length);
	if(b64 == NULL || len <= 0)
		return 0;

	if(b64) BIO_free_all(b64);
	return len;
}
