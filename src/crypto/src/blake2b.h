/**
 * blake2b.h - Blake2b hash function support header
 *
 * For more information, please refer to ./blake2b.c
 *
 * Date: 22 April 2020
 * Revised: 16 August 2021
 *
*/

#ifndef _BLAKE2B_H_
#define _BLAKE2B_H_  /* include guard */


#include <stddef.h>
#include <stdint.h>

#ifndef BLAKE2BLEN256
#define BLAKE2BLEN256  32
#endif

#ifndef BLAKE2BLEN384
#define BLAKE2BLEN384  48
#endif

#ifndef BLAKE2BLEN512
#define BLAKE2BLEN512  64
#endif

#ifndef BLAKE2B_ROUNDS
#define BLAKE2B_ROUNDS  12
#endif

#ifndef ROTR64
#define ROTR64(x, y)  ( ((x) >> (y)) ^ ((x) << (64 - (y))) )
#endif

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


#ifdef __cplusplus
extern "C" {
#endif

/* Blake2b context */
typedef struct {
   union {               /* input buffer: */
      uint8_t b[128];    /* 8-bit bytes   */
      uint64_t q[16];    /* 64-bit words  */
   } in;
   uint64_t h[8];        /* chained state */
   uint64_t t/* [2] */;  /* total number of bytes */
   size_t c;             /* pointer for in.b[] */
   size_t outlen;        /* digest size */
} BLAKE2B_CTX;

/* Initialize the hashing context `ctx` with optional key `key`.
 * Set outlen= 32/48/64 for digest bit lengths 256/384/512 respectively.
 * For "no key" usage, set key= NULL and keylen= 0. */
int blake2b_init(BLAKE2B_CTX *ctx, const void *key, int keylen, int outlen);

/* Add `inlen` bytes from `in` into the hash */
void blake2b_update(BLAKE2B_CTX *ctx, const void *in, size_t inlen);

/* Generate the message digest and place in `out` */
void blake2b_final(BLAKE2B_CTX *ctx, void *out);

/* Convenient all-in-one Blake2b computation */
int blake2b(const void *in, size_t inlen, const void *key, int keylen,
   void *out, int outlen);

#ifdef __cplusplus
}
#endif


#endif  /* end _BLAKE2B_H_ */
