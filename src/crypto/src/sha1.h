/**
 * sha1.h - SHA1 hash function support header
 *
 * For more information, please refer to ./sha1.c
 *
 * Date: 8 April 2020
 * Revised: 26 October 2021
 *
*/

#ifndef _CRYPTO_SHA1_H_
#define _CRYPTO_SHA1_H_  /* include guard */


#include <stddef.h>  /* for size_t */
#include "extint.h"  /* for word types */

/* 32-bit rotate left definition */
#ifndef ROTL32
#define ROTL32(a,b)  ( ((a) << (b)) | ((a) >> (32-(b))) )
#endif

/* SHA1 specific parameters */
#define SHA1LEN  20

/* SHA1 context */
typedef struct {
   word8 data[64];
   word32 datalen;
   word32 bitlen[2];
   word32 state[5];
} SHA1_CTX;

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for sha1.c */
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const void *in, size_t inlen);
void sha1_final(SHA1_CTX *ctx, void *out);
void sha1(const void *in, size_t inlen, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRYPTO_SHA1_H_ */
