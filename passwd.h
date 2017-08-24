#ifndef __PASSWD_H__
#define __PASSWD_H__

#ifdef __cplusplus
extern "C"
{
#endif

int passwd_encrypt(const unsigned char *input, int input_length, unsigned char *output, int output_length);
int passwd_decrypt(const unsigned char *input, int input_length, unsigned char *output, int output_length);

#ifdef __cplusplus
}
#endif

#endif /* __PASSWD_H__ */
