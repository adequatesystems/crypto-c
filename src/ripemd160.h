/**
 * @file ripemd160.h
 * @brief RIPEMD160 hash function support.
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
 * @note Consider the tricks used by...
 * > <https://github.com/DaveCTurner/tiny-ripemd160/blob/main/ripemd160.c>
 * ... to derive the index of constants, when performing optimizations
 */

/* include guard */
#ifndef CRYPTO_RIPEMD160_H
#define CRYPTO_RIPEMD160_H


#include "utildev.h"

#define RIPEMDLEN160 20 /**< RIPEMD 160-bit digest length, in bytes */

typedef struct {
   uint8_t buffer[64];  /**< input buffer */
   uint32_t state[5];   /**< internal hashing state */
   size_t total;        /**< total number of bytes processed */
} RIPEMD160_CTX;  /**< RIPEMD160 context */

/* C/C++ compatible function prototypes */
#ifdef __cplusplus
extern "C" {
#endif

void ripemd160_init(RIPEMD160_CTX *ctx);
void ripemd160_update(RIPEMD160_CTX *ctx, const void *in, size_t inlen);
void ripemd160_final(RIPEMD160_CTX *ctx, void *out);
void ripemd160(const void *in, size_t inlen, uint8_t *out);

/* end extern "C" {} for C++ */
#ifdef __cplusplus
}
#endif

/* end include guard */
#endif
