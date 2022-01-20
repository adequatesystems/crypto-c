/**
 * @file sha256.h
 * @brief SHA256 hash function support.
 * @details This file is based on Brad Conte's basic
 * implementations of cryptography algorithms...
 * > <https://github.com/B-Con/crypto-algorithms>
 * ... and alterations to the transform function were based on
 * Igor Pavlov's SHA256 implementation...
 * > <https://github.com/jb55/sha256.c>
 * ... both of which were released into the Public Domain.
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

/* include guard */
#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H


#include "utildev.h"

#define SHA256LEN 32 /**< SHA256 message digest length, in bytes */

typedef struct {
   uint8_t data[64];    /**< Input buffer */
   uint32_t bitlen[2];  /**< Total bit length of updated input */
   uint32_t state[8];   /**< Internal hashing state */
   uint32_t datalen;    /**< Length of buffered input */
   /**
    * 256-bit alignment padding. Does nothing beyond ensuring
    * a list of contexts that begin 256-bit aligned, remain
    * similarly aligned for every item in said list.
   */
   uint32_t balign256[5];
} SHA256_CTX;  /**< SHA256 Context */

/* C/C++ compatible function prototypes */
#ifdef __cplusplus
extern "C" {
#endif

HOST_DEVICE_FN void sha256_init(SHA256_CTX *ctx);
HOST_DEVICE_FN void sha256_update(
   SHA256_CTX *ctx, const void *in, size_t inlen);
HOST_DEVICE_FN void sha256_final(SHA256_CTX *ctx, void *out);
HOST_DEVICE_FN void sha256(const void *in, size_t inlen, void *out);

/* end extern "C" {} for C++ */
#ifdef __cplusplus
}
#endif

/* end include guard */
#endif
