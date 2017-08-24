#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include "base64.h"

int passwd_encrypt(const unsigned char *input, int input_length, unsigned char *output, int output_length)
{
    int loop = 0;
    int padding = 0;
    int length = 0;
    unsigned char *buffer = NULL;

    unsigned char iv[16] =  {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    unsigned char key[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    AES_KEY enc;

    if(input == NULL || input_length <= 0 || output == NULL || output_length <= 0)
        return -1;

    padding = AES_BLOCK_SIZE - (input_length % AES_BLOCK_SIZE);
    length = input_length + padding;

    buffer = (unsigned char*)malloc(length*sizeof(unsigned char));
    if(buffer == NULL)
        return -1;
    memset(buffer, 0, length*sizeof(unsigned char));

    memcpy(buffer, input, input_length);
    for(loop = 0; loop < padding;  loop ++)
        buffer[input_length + loop] = padding;

    AES_set_encrypt_key(key, 128, &enc);
    AES_cbc_encrypt(buffer, output, length, &enc, iv, AES_ENCRYPT);

    length = base64encode(output, length, output, output_length);

    if(buffer) free(buffer);
    return length;
}

int passwd_decrypt(const unsigned char *input, int input_length, unsigned char *output, int output_length)
{
    int padding = 0;
    int length = 0;

    unsigned char iv[16] =  {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    unsigned char key[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    AES_KEY dec;

    if(input == NULL || input_length <= 0 || output == NULL || output_length <= 0)
        return -1;

    length = base64decode(input, input_length, output, output_length);
    if(length <= 0)
        return -1;

    AES_set_decrypt_key(key, 128, &dec);
    AES_cbc_encrypt(output, output, length, &dec, iv, AES_DECRYPT);

    padding = output[length-1];
    length = length - padding;

    output[length] = 0;
    return length;
}
