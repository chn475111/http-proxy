#ifndef __BASE64_H__
#define __BASE64_H__

#ifdef __cplusplus
extern "C"
{
#endif

int base64encode(const unsigned char *input, int input_length, unsigned char *output, int output_length);
int base64decode(const unsigned char *input, int input_length, unsigned char *output, int output_length);

#ifdef __cplusplus
}
#endif

#endif
