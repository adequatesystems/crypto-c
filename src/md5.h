/**
 * @file md5.h
 * @brief MD5 hash function support.
 * @details This file is based on Brad Conte's basic
 * implementations of cryptography algorithms...
 * > <https://github.com/B-Con/crypto-algorithms>
 * ... which was released into the Public Domain.
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

/* include guard */
#ifndef CRYPTO_MD5_H
#define CRYPTO_MD5_H


#include "utildev.h"

#define MD5LEN  16   /**< MD5 message digest length, in bytes */

/* MD5 specific routines */
#define F(x,y,z)  ( (x & y) | (~x & z) )
#define G(x,y,z)  ( (x & z) | (y & ~z) )
#define H(x,y,z)  ( x ^ y ^ z )
#define I(x,y,z)  ( y ^ (x | ~z) )
#define FF(a,b,c,d,m,s,t)  { a += F(b,c,d) + m + t; a = b + rol32(a,s); }
#define GG(a,b,c,d,m,s,t)  { a += G(b,c,d) + m + t; a = b + rol32(a,s); }
#define HH(a,b,c,d,m,s,t)  { a += H(b,c,d) + m + t; a = b + rol32(a,s); }
#define II(a,b,c,d,m,s,t)  { a += I(b,c,d) + m + t; a = b + rol32(a,s); }

typedef struct {
   uint8_t data[64];    /**< Input buffer */
   uint32_t state[4];   /**< Internal hashing state */
   uint32_t bitlen[2];  /**< Total bit length */
   uint32_t datalen;    /**< Length of buffered input */
   /**
    * 256-bit alignment padding. Does nothing beyond ensuring
    * a list of contexts that begin 256-bit aligned, remain
    * similarly aligned for every item in said list.
   */
   uint32_t balign256[1];
} MD5_CTX;  /**< MD5 Context */

/* C/C++ compatible function prototypes */
#ifdef __cplusplus
extern "C" {
#endif

void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const void *in, size_t inlen);
void md5_final(MD5_CTX *ctx, void *out);
void md5(const void *in, size_t inlen, void *out);

/* CUDA testing functions */
#ifdef CUDA
   void test_kcu_md5(const void *in, size_t *inlen, size_t max_inlen,
      void *out, int num);
#endif

/* end extern "C" {} for C++ */
#ifdef __cplusplus
}
#endif

/* end include guard */
#endif
