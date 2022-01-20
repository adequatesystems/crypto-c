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

typedef struct {
   uint8_t data[64];    /**< Input buffer */
   uint32_t bitlen[2];  /**< Total bit length of updated input */
   uint32_t state[5];   /**< Internal hashing state */
   uint32_t datalen;    /**< Length of buffered input */
   /**
    * 256-bit alignment padding. Does nothing beyond ensuring
    * a list of contexts that begin 256-bit aligned, remain
    * similarly aligned for every item in said list.
   */
   uint32_t balign256[3];
} SHA1_CTX;  /**< SHA1 Context */

/* C/C++ compatible function prototypes */
#ifdef __cplusplus
extern "C" {
#endif

HOST_DEVICE_FN void sha1_init(SHA1_CTX *ctx);
HOST_DEVICE_FN void sha1_update(SHA1_CTX *ctx, const void *in, size_t inlen);
HOST_DEVICE_FN void sha1_final(SHA1_CTX *ctx, void *out);
HOST_DEVICE_FN void sha1(const void *in, size_t inlen, void *out);

/* end extern "C" {} for C++ */
#ifdef __cplusplus
}
#endif

/* end include guard */
#endif
