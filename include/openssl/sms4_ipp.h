#ifdef OPENSSL_WITH_INTEL
#ifndef __SMS4_IPP_H__
#define __SMS4_IPP_H__
#include <stdint.h>
#include "ippcore.h"
#include "ippcp.h"

enum
{
    SM4_SUCCESS,
    SM4_BAD_KEY,
    SM4_CBC_ENCRYPT_FAILED,
    SM4_CBC_DECRYPT_FAILED
};

#ifdef  __cplusplus
extern "C"
{
#endif

	int sm4_cbc_encrypt (const uint8_t * in, const uint32_t in_len_bytes,
						 uint8_t * out, const uint8_t * key,
						 const uint32_t key_len_bytes, const uint8_t ivec[16]);
	int sm4_cbc_decrypt (const uint8_t * in, const uint32_t in_len_bytes,
						 uint8_t * out, uint32_t * const out_len_bytes,
						 const uint8_t * key, const uint32_t key_len_bytes,
						 const uint8_t ivec[16]);
#ifdef __cplusplus
}
#endif

#endif
#endif
