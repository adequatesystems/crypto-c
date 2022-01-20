/**
 * blake2b.h - Blake2b hash function support header
 *
 * For more information, please refer to ./blake2b.c
 *
 * Date: 22 April 2020
 * Revised: 26 October 2021
 *
*/

#ifndef _CRYPTO_BLAKE2B_H_
#define _CRYPTO_BLAKE2B_H_  /* include guard */


#include <stddef.h>  /* for size_t */
#include "extint.h"  /* for word types */

/* 64-bit rotate right definition */
#ifndef ROTR64
#define ROTR64(x, y)  ( ((x) >> (y)) ^ ((x) << (64 - (y))) )
#endif

/* Blake2b specific parameters */
#define BLAKE2BLEN256  32
#define BLAKE2BLEN384  48
#define BLAKE2BLEN512  64
#define BLAKE2BROUNDS  12

/* G Mixing function */
#define B2B_G(a, b, c, d, x, y)    \
   v[a] = v[a] + v[b] + x;         \
   v[d] = ROTR64(v[d] ^ v[a], 32); \
   v[c] = v[c] + v[d];             \
   v[b] = ROTR64(v[b] ^ v[c], 24); \
   v[a] = v[a] + v[b] + y;         \
   v[d] = ROTR64(v[d] ^ v[a], 16); \
   v[c] = v[c] + v[d];             \
   v[b] = ROTR64(v[b] ^ v[c], 63);

/* Blake2b context */
typedef struct {
   union {  /* input buffer: */
      word8 b[128];     /* 8-bit bytes   */
      word64 q[16];     /* 64-bit words  */
   } in;  /* end input buffer */
   word64 h[8];         /* chained state */
   word64 t/* [2] */;   /* total number of bytes */
   size_t c;            /* pointer for in.b[] */
   size_t outlen;       /* digest size */
} BLAKE2B_CTX;

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for blake2b.c */
int blake2b_init(BLAKE2B_CTX *ctx, const void *key, int keylen, int outlen);
void blake2b_update(BLAKE2B_CTX *ctx, const void *in, size_t inlen);
void blake2b_final(BLAKE2B_CTX *ctx, void *out);
int blake2b(const void *in, size_t inlen, const void *key, int keylen,
   void *out, int outlen);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRYPTO_BLAKE2B_H_ */
