/**
 * @file blake2b.h
 * @brief Blake2b hash function support.
 * @details This file is based on Dr. Markku-Juhani O. Saarinen's
 * "somewhat smaller" BLAKE2 implemetation...
 * > <https://github.com/mjosaarinen/blake2_mjosref><br/>
 * ... which was released into the Public Domain under the
 * Creative Commons Zero v1.0 Universal license.
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

/* include guard */
#ifndef CRYPTO_BLAKE2B_H
#define CRYPTO_BLAKE2B_H


#include "utildev.h"

#define BLAKE2BLEN256   32  /**< 256-bit Blake2b digest length in bytes */
#define BLAKE2BLEN384   48  /**< 384-bit Blake2b digest length in bytes */
#define BLAKE2BLEN512   64  /**< 512-bit Blake2b digest length in bytes */

typedef struct {
   union {
      uint8_t b[128];   /**< 8-bit input buffer */
      uint64_t q[16];   /**< 64-bit input buffer */
   } in;                /**< Input buffer union */
   uint64_t h[8];       /**< Internal hashing state */
   uint64_t t[2];       /**< Total number of bytes */
   uint64_t c;          /**< Length of buffered input */
   uint64_t outlen;     /**< Digest length */
} BLAKE2B_CTX;    /**< Blake2b context */

/* C/C++ compatible function prototypes */
#ifdef __cplusplus
extern "C" {
#endif

HOST_DEVICE_FN int blake2b_init(
   BLAKE2B_CTX *ctx, const void *key, int keylen, int outlen);
HOST_DEVICE_FN void blake2b_update(
   BLAKE2B_CTX *ctx, const void *in, size_t inlen);
HOST_DEVICE_FN void blake2b_final(BLAKE2B_CTX *ctx, void *out);
HOST_DEVICE_FN int blake2b(
   const void *in, size_t inlen, const void *key, int keylen,
   void *out, int outlen);

/* end extern "C" {} for C++ */
#ifdef __cplusplus
}
#endif

/* end include guard */
#endif
