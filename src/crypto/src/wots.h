/**
 * wots.h - WOTS+ Public address, Signature, and Verification header
 *
 * Copyright (c) 2018-2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 25 May 2018
 * Revised: 17 September 2021
 *
 * For more information on the implementation, please refer to ./wots.c
 *
*/

#ifndef _SIGN_WOTS_H_
#define _SIGN_WOTS_H_


#include <stdint.h>

#define core_hash(out, in, inlen) sha256(in, inlen, out)

/* Parameters */
#define XMSS_HASH_PADDING_F 0
#define XMSS_HASH_PADDING_PRF 3

#define WOTSW      16
#define WOTSLOGW   4
#define WOTSLEN    (WOTSLEN1 + WOTSLEN2)
#define WOTSLEN1   (8 * PARAMSN / WOTSLOGW)
#define WOTSLEN2   3
#define WOTSSIGBYTES (WOTSLEN * PARAMSN)
#define PARAMSN 32

/* 2144 + 32 + 32 = 2208 */
#define TXSIGLEN   2144
#define TXADDRLEN  2208

#ifdef __cplusplus
extern "C" {
#endif

/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pkgen(uint8_t *pk, const uint8_t *seed,
                const uint8_t *pub_seed, uint32_t addr[8]);

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void wots_sign(uint8_t *sig, const uint8_t *msg,
               const uint8_t *seed, const uint8_t *pub_seed,
               uint32_t addr[8]);

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(uint8_t *pk,
                      const uint8_t *sig, const uint8_t *msg,
                      const uint8_t *pub_seed, uint32_t addr[8]);

#ifdef __cplusplus
}
#endif


#endif  /* end _SIGN_WOTS_H_ */
