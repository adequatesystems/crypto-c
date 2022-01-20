/**
 * sha256.h - SHA256 hash function support header
 *
 * For more information, please refer to ./sha256.c
 *
 * Date: 8 April 2020
 * Revised: 26 October 2021
 *
*/

#ifndef _CRYPTO_SHA256_H_
#define _CRYPTO_SHA256_H_  /* include guard */


#include <stddef.h>  /* for size_t */
#include "extint.h"  /* for word types */

/* 32-bit rotate right definition */
#ifndef ROTR32
#define ROTR32(a,b)  ( ((a) >> (b)) | ((a) << (32-(b))) )
#endif

/* SHA256 specific parameters */
#define SHA256LEN    32
#define SHA256ROUNDS 64

/* SHA256 specific routines */
#define CH(x,y,z)  ( ((x) & (y)) ^ (~(x) & (z)) )
#define MAJ(x,y,z)  ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) )
#define EP0(x)  ( ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22) )
#define EP1(x)  ( ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25) )
#define SIG0(x)  ( ROTR32(x,7) ^ ROTR32(x,18) ^ ((x) >> 3) )
#define SIG1(x)  ( ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10) )

/* SHA256 context */
typedef struct {
   word8 data[64];
   word32 datalen;
   word32 bitlen[2];
   word32 state[8];
} SHA256_CTX;

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for sha256.c */
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const void *in, size_t inlen);
void sha256_final(SHA256_CTX *ctx, void *out);
void sha256(const void *in, size_t inlen, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRYPTO_SHA256_H_ */