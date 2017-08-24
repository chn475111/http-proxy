#ifdef OPENSSL_WITH_INTEL
#ifndef __SM2_IPP_H__
#define __SM2_IPP_H__
#include <stdint.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "ippcore.h"
#include "ippcp.h"

#define SM2_BITS 256
#define SM2_INTS 8

#ifdef  __cplusplus
extern "C"
{
#endif
    int sm2_sign_hash (const uint8_t * msg_hash, const uint32_t msg_hash_len,
                       const uint8_t * priv_key, const uint32_t priv_key_length,
                       unsigned char *signature, uint32_t * const siglen);

    int sm2_verify_hash (const uint8_t * signature, const uint32_t sign_length,
                         const uint8_t * msg_hash,
                         const uint32_t msg_hash_length,
                         const uint8_t * pub_key,
                         const uint32_t pub_key_length);

    /* SM2 encrypt */
    int sm2_encrypt (uint8_t * const ciphertext,
                     uint32_t * const ciphertext_len_bytes,
                     const uint8_t * plaintext,
                     const uint32_t plaintext_len_bytes,
                     const uint8_t * public_key,
                     const uint32_t public_key_len_bytes);
    /* SM2 decrypt */
    int sm2_decrypt (uint8_t * const outputtext,
                     uint32_t * const outputtext_len_bytes,
                     const uint8_t * ciphertext,
                     const uint32_t ciphertext_len_bytes,
                     const uint8_t * private_key,
                     const uint32_t private_key_len_bytes);

    int sm2_compute_key_with_option (const uint8_t * const peer_random_point,
                             const uint32_t peer_random_point_len_bytes,
                             const uint8_t * const peer_public_key,
                             const uint32_t peer_public_key_len_bytes,
                             const uint8_t * const self_public_key,
                             const uint32_t self_public_key_len_bytes,
                             const uint8_t * const self_random,
                             const uint32_t self_random_len_bytes,
                             const uint8_t * const self_random_point,
                             const uint32_t self_random_point_len_bytes,
                             const uint8_t * const peer_id,
                             const uint32_t peer_id_len_bytes,
                             const uint8_t * const self_id,
                             const uint32_t self_id_len_bytes,
                             const uint8_t * const self_private_key,
                             const uint32_t self_private_key_len_bytes,
                             uint8_t * const session_key,
                             const uint32_t session_key_len_bytes,
                             const uint32_t self_option_flag,
                             uint8_t * const self_option,
                             uint32_t * const self_option_len_bytes,
                             uint8_t * const option_verify,
                             uint32_t * const option_verify_len_bytes,
                             uint32_t const is_sponsor);

	// unsigned char pubkey[64+1];
	int get_pubkey_from_ec_key(EC_KEY *ec_key, unsigned char *out, unsigned int len);
	// unsigned char prikey[32+1];
	int get_prikey_from_ec_key(EC_KEY *ec_key, unsigned char *out);
#ifdef __cplusplus
}
#endif
#endif
#endif
