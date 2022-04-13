/**
 * @file sha1.h
 * @brief SHA1 hash function support.
 * @details This file is based on Brad Conte's basic
 * implementations of cryptography algorithms...
 * > <https://github.com/B-Con/crypto-algorithms>
 * ... and alterations to the transform function were based on
 * Steve Reid's SHA1 implementation...
 * > <https://github.com/clibs/sha1>
 * ... both of which were released into the Public Domain.
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

/* include guard */
#ifndef CRYPTO_SHA1_H
#define CRYPTO_SHA1_H


#include "utildev.h"

#define SHA1LEN   20 /**< SHA1 message digest length, in bytes */

/* SHA1 transform routines */
#define sha1_blk0(i)  ( W[i] = bswap32(W[i]) )
#define sha1_blk_xor4(i) \
   xor4(W[(i + 13) & 15], W[(i + 8) & 15], W[(i + 2) & 15], W[i & 15])
#define sha1_blk(i) ( W[i & 15] = rol32(sha1_blk_xor4(i), 1) )
/* SHA1 round1 input */
#define sha1_r0(a, b, c, d, e, i) \
   e += xandx(b, c, d) + sha1_blk0(i) + k[0] + rol32(a, 5); \
   b = rol32(b, 30)
/* SHA1 round1 extended */
#define sha1_r1(a, b, c, d, e, i) \
   e += xandx(b, c, d) + sha1_blk(i) + k[0] + rol32(a, 5); \
   b = rol32(b, 30)
/* SHA1 rounds 2/3/4 */
#define sha1_r2(a, b, c, d, e, i) \
   e += xor3(b, c, d) + sha1_blk(i) + k[1] + rol32(a, 5); \
   b = rol32(b, 30)
#define sha1_r3(a, b, c, d, e, i) \
   e += (((b | c) & d) | (b & c)) + sha1_blk(i) + k[2] + rol32(a, 5); \
   b = rol32(b, 30)
#define sha1_r4(a, b, c, d, e, i) \
   e += xor3(b, c, d) + sha1_blk(i) + k[3] + rol32(a, 5); \
   b = rol32(b, 30)

typedef struct {
   uint8_t data[64];    /**< Input buffer */
   uint32_t bitlen[2];  /**< Total bit length of updated input */
   uint32_t state[5];   /**< Internal hashing state */
   uint32_t datalen;    /**< Length of buffered input */
} SHA1_CTX;  /**< SHA1 Context */

/* C/C++ compatible function prototypes */
#ifdef __cplusplus
extern "C" {
#endif

void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const void *in, size_t inlen);
void sha1_final(SHA1_CTX *ctx, void *out);
void sha1(const void *in, size_t inlen, void *out);

/* CUDA testing functions */
#ifdef CUDA
   void test_kcu_sha1(const void *in, size_t *inlen, size_t max_inlen,
      void *out, int num);
#endif

/* end extern "C" {} for C++ */
#ifdef __cplusplus
}
#endif

/* end include guard */
#endif
