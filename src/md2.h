/**
 * @file md2.h
 * @brief MD2 hash function support.
 * @details This file is based on Brad Conte's basic
 * implementations of cryptography algorithms...
 * > <https://github.com/B-Con/crypto-algorithms>
 * ... which was released into the Public Domain.
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

#ifndef CRYPTO_MD2_H
#define CRYPTO_MD2_H  /* include guard */


#include "utildev.h"

#define MD2LEN 16   /**< MD2 message digest length, in bytes */

typedef struct {
   uint8_t state[48];      /**< Internal hashing state */
   uint8_t checksum[16];   /**< Internal hashing checksum */
   uint8_t data[16];       /**< Input buffer */
   uint32_t datalen;       /**< Length of buffered input */
} MD2_CTX;  /**< MD2 context */

/* C/C++ compatible function prototypes */
#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for md2.c */
void md2_init(MD2_CTX *ctx);
void md2_update(MD2_CTX *ctx, const void *in, size_t inlen);
void md2_final(MD2_CTX *ctx, void *out);
void md2(const void *in, size_t inlen, void *out);

/* CUDA testing functions */
#ifdef CUDA
   void test_kcu_md2(const void *in, size_t *inlen, size_t max_inlen,
      void *out, int num);
#endif

/* end extern "C" {} for C++ */
#ifdef __cplusplus
}
#endif

/* end include guard */
#endif
