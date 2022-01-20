/**
 * sha3.h - SHA3 and Keccak hash function support header
 *
 * For more information, please refer to ./sha3.c
 *
 * Date: 22 April 2020
 * Revised: 26 October 2021
 *
*/

#ifndef _CRYPTO_SHA3_H_
#define _CRYPTO_SHA3_H_  /* include guard */


#include <stddef.h>  /* for size_t */
#include "extint.h"

/* 64-bit rotate left definition */
#ifndef ROTL64
#define ROTL64(x, y)  ( ((x) << (y)) | ((x) >> (64 - (y))) )
#endif

/* SHA3 specific parameters */
#define SHA3LEN224      28
#define SHA3LEN256      32
#define SHA3LEN384      48
#define SHA3LEN512      64
#define KECCAKLEN224    28
#define KECCAKLEN256    32
#define KECCAKLEN384    48
#define KECCAKLEN512    64
#define KECCAKFROUNDS   24

/* SHA3 init and update routines mimmick keccak */
#define keccak_init(c, len)          sha3_init(c, len)
#define keccak_update(c, data, len)  sha3_update(c, data, len)

/* SHA3 context */
typedef struct {
   union {  /* state: */
      word8 b[200];  /*  8-bit bytes  */
      word32 d[50];  /*  32-bit words */
      word64 q[25];  /*  64-bit words */
   } st;
   int pt, rsiz, outlen;  /* these don't overflow */
} SHA3_CTX;
typedef SHA3_CTX  KECCAK_CTX;

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for sha3.c */
void sha3_init(SHA3_CTX *ctx, int outlen);
void sha3_update(SHA3_CTX *ctx, const void *in, size_t inlen);
void sha3_final(SHA3_CTX *ctx, void *out);
void keccak_final(SHA3_CTX *ctx, void *out);
void sha3(const void *in, size_t inlen, void *out, int outlen);
void keccak(const void *in, size_t inlen, void *out, int outlen);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRYPTO_SHA3_H_ */
