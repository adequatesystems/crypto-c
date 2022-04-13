/**
 * @file sha3.h
 * @brief SHA3 hash function support.
 * @details This file is based on Dr. Markku-Juhani O. Saarinen's
 * "cooked up" compact and readable keccak implemetation...
 * > <https://github.com/mjosaarinen/tiny_sha3>
 * ... which was released under the MIT license (MIT).
 * <br/><br/>
 * Alterations to the transform function were based on
 * Marko Kreen's optimized C implementation...
 * > <https://github.com/markokr/spongeshaker>
 * ... which was released under the ISC License (ISC).
 *
 * @copyright 2014 Marko Kreen <markokr@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * @copyright 2015 Markku-Juhani O. Saarinen <mjos@iki.fi>
 * @copyright 2020-2022 Adequate Systems, LLC.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * * The above copyright notice and this permission notice shall be
 *   included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
*/

/* include guard */
#ifndef CRYPTO_SHA3_H
#define CRYPTO_SHA3_H


#include "utildev.h"

#define SHA3LEN224      28 /**< SHA3 224-bit digest length, in bytes */
#define SHA3LEN256      32 /**< SHA3 256-bit digest length, in bytes */
#define SHA3LEN384      48 /**< SHA3 384-bit digest length, in bytes */
#define SHA3LEN512      64 /**< SHA3 512-bit digest length, in bytes */
#define KECCAKLEN224    28 /**< KECCAK 224-bit digest length, in bytes */
#define KECCAKLEN256    32 /**< KECCAK 256-bit digest length, in bytes */
#define KECCAKLEN384    48 /**< KECCAK 384-bit digest length, in bytes */
#define KECCAKLEN512    64 /**< KECCAK 512-bit digest length, in bytes */

#define KECCAKFROUNDS   24

/**
 * SHA3/Keccak hashing context
*/
typedef struct {
   union {
      uint8_t b[200];   /**< 8-bit input buffer */
      uint64_t q[25];   /**< 64-bit input buffer */
   } st;                /**< Input buffer union */
   uint32_t outlen;     /**< Digest length, in bytes */
   uint32_t rsiz;       /**< Rate size, in bytes */
   uint32_t pt;         /**< Length of buffered input */
} SHA3_KECCAK_CTX;

/* C/C++ compatible function prototypes */
#ifdef __cplusplus
extern "C" {
#endif

void sha3_init(SHA3_KECCAK_CTX *ctx, int outlen);
void sha3_update(SHA3_KECCAK_CTX *ctx, const void *in, size_t inlen);
void sha3_final(SHA3_KECCAK_CTX *ctx, void *out);
void sha3(const void *in, size_t inlen, void *out, int outlen);
void keccak_init(SHA3_KECCAK_CTX *ctx, int outlen);
void keccak_update(SHA3_KECCAK_CTX *ctx, const void *in, size_t inlen);
void keccak_final(SHA3_KECCAK_CTX *ctx, void *out);
void keccak(const void *in, size_t inlen, void *out, int outlen);

/* CUDA testing functions */
#ifdef CUDA
   void test_kcu_sha3(const void *in, size_t *inlen, size_t max_inlen,
      void *out, int outlen, int num);
   void test_kcu_keccak(const void *in, size_t *inlen, size_t max_inlen,
      void *out, int outlen, int num);
#endif

/* end extern "C" {} for C++ */
#ifdef __cplusplus
}
#endif

/* end include guard */
#endif
