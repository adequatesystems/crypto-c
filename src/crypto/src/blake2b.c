/**
 * blake2b.c - Blake2b hash function support
 *
 * Based on Dr. Markku-Juhani O. Saarinen's (mjos@iki.fi)
 * "somewhat smaller" BLAKE2 implemetation,
 *    <https://github.com/mjosaarinen/blake2_mjosref>
 * which was released into the Public Domain under the Creative
 * Commons Zero (CC0) v1.0 Universal license and is therefore used
 * with permission, and with much gratitude.  \(^-^)/
 *
 * For more information, please refer to ../LICENSE.UNLICENSE
 *
 * Date: 22 April 2020
 * Revised: 17 August 2021
 *
 * NOTES:
 * - Presently, due to heavy reliance on 64-bit operations, this
 *   implementation CANNOT RUN on systems that rely on C89 compliance.
 * - This implementation supports the Blake2b algorithm for 256, 384
 *   and 512 bit message digests on x86_64 little endian hardware,
 *   using modified routines for faster Blake2b compressions.
 * - This implementation removes the 128-bit "total bytes" context
 *   variable and operations in favour of a 64-bit alternate. To
 *   restore the 128-bit functionality, simply remove the comment
 *   notation throughout this file and it's associated header file.
 *
*/

#ifndef _CRYPTO_BLAKE2B_C_
#define _CRYPTO_BLAKE2B_C_  /* include guard */


#include "blake2b.h"

/* Blake2b initialization vector */
static const word64 Blake2b_iv[8] = {
   0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
   0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
   0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
   0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

/* Blake2b compression Sigma */
static const word8 Sigma[12][16] = {
   { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
   { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
   { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
   { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
   { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
   { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
   { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
   { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
   { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
   { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
   { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
   { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

/* Compression function, `last` flag indicates last block. */
static void blake2b_compress(BLAKE2B_CTX *ctx, int last)
{
   word64 v[16];
   int i;

   v[0] = ctx->h[0];
   v[1] = ctx->h[1];
   v[2] = ctx->h[2];
   v[3] = ctx->h[3];
   v[4] = ctx->h[4];
   v[5] = ctx->h[5];
   v[6] = ctx->h[6];
   v[7] = ctx->h[7];
   v[8] = Blake2b_iv[0];
   v[9] = Blake2b_iv[1];
   v[10] = Blake2b_iv[2];
   v[11] = Blake2b_iv[3];
   v[12] = Blake2b_iv[4];
   v[13] = Blake2b_iv[5];
   v[14] = Blake2b_iv[6];
   v[15] = Blake2b_iv[7];

   v[12] ^= ctx->t/* [0] */;
   /* v[13] ^= ctx->t[1]; */
   if (last) {
      v[14] = ~v[14];
   }

   for (i = 0; i < BLAKE2BROUNDS; i++) {
      B2B_G( 0, 4,  8, 12, ctx->in.q[Sigma[i][ 0]], ctx->in.q[Sigma[i][ 1]]);
      B2B_G( 1, 5,  9, 13, ctx->in.q[Sigma[i][ 2]], ctx->in.q[Sigma[i][ 3]]);
      B2B_G( 2, 6, 10, 14, ctx->in.q[Sigma[i][ 4]], ctx->in.q[Sigma[i][ 5]]);
      B2B_G( 3, 7, 11, 15, ctx->in.q[Sigma[i][ 6]], ctx->in.q[Sigma[i][ 7]]);
      B2B_G( 0, 5, 10, 15, ctx->in.q[Sigma[i][ 8]], ctx->in.q[Sigma[i][ 9]]);
      B2B_G( 1, 6, 11, 12, ctx->in.q[Sigma[i][10]], ctx->in.q[Sigma[i][11]]);
      B2B_G( 2, 7,  8, 13, ctx->in.q[Sigma[i][12]], ctx->in.q[Sigma[i][13]]);
      B2B_G( 3, 4,  9, 14, ctx->in.q[Sigma[i][14]], ctx->in.q[Sigma[i][15]]);
   }

   ctx->h[0] ^= v[0] ^ v[8];
   ctx->h[1] ^= v[1] ^ v[9];
   ctx->h[2] ^= v[2] ^ v[10];
   ctx->h[3] ^= v[3] ^ v[11];
   ctx->h[4] ^= v[4] ^ v[12];
   ctx->h[5] ^= v[5] ^ v[13];
   ctx->h[6] ^= v[6] ^ v[14];
   ctx->h[7] ^= v[7] ^ v[15];
}  /* end blake2b_compress() */

/* Add `inlen` bytes from `in` into the hash */
void blake2b_update(BLAKE2B_CTX *ctx, const void *in, size_t inlen)
{
   size_t i;

   for (i = 0; i < inlen; i++) {
      if (ctx->c == 128) {
         ctx->t/* [0] */ += ctx->c;
         /* if (ctx->t[0] < ctx->c) ctx->t[1]++; */
         blake2b_compress(ctx, 0);
         ctx->c = 0;
      }
      ctx->in.b[ctx->c++] = ((const word8 *) in)[i];
   }
}  /* end blake2b_update() */

/* Initialize the hashing context `ctx` with optional key `key`.
 * Set outlen= 32/48/64 for digest bit lengths 256/384/512 respectively.
 * For "no key" usage, set key= NULL and keylen= 0. */
int blake2b_init(BLAKE2B_CTX *ctx, const void *key, int keylen, int outlen)
{
   int i;

   if ((outlen != 32 && outlen != 48 && outlen != 64) || keylen > 64) {
      return -1;
   }

   for (i = 0; i < 8; i++) {
      ctx->h[i] = Blake2b_iv[i];
   }
   ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

   ctx->t/* [0] */ = 0;
   /* ctx->t[1] = 0; */
   ctx->c = 0;
   ctx->outlen = outlen;

   for (i = keylen; i & 0x07; i++) {
      ctx->in.b[i] = 0;
   }
   for (i >>= 3; i < 16; i++) {
      ctx->in.q[i] = 0;
   }

   if (keylen > 0) {
      blake2b_update(ctx, key, keylen);
      ctx->c = 128;
   }

   return 0;
}  /* end blake2b_init() */

/* Generate the message digest and place in `out` */
void blake2b_final(BLAKE2B_CTX *ctx, void *out)
{
   size_t i;

   ctx->t/* [0] */ += ctx->c;
   /* if (ctx->t[0] < ctx->c) ctx->t[1]++; */

   for (i = ctx->c; i & 7; i++) {
      ctx->in.b[i] = 0;
   }
   for (i >>= 3; i < 16; i++) {
      ctx->in.q[i] = 0;
   }

   blake2b_compress(ctx, 1);

   /* 256-bit digest */
   ((word64 *) out)[0] = ctx->h[0];
   ((word64 *) out)[1] = ctx->h[1];
   ((word64 *) out)[2] = ctx->h[2];
   ((word64 *) out)[3] = ctx->h[3];
   if (ctx->outlen <= 32) return;

   /* 384-bit digest */
   ((word64 *) out)[4] = ctx->h[4];
   ((word64 *) out)[5] = ctx->h[5];
   if (ctx->outlen <= 48) return;

   /* 512-bit digest */
   ((word64 *) out)[6] = ctx->h[6];
   ((word64 *) out)[7] = ctx->h[7];
}  /* end blake2b_final() */

/* Convenient all-in-one Blake2b computation */
int blake2b(const void *in, size_t inlen, const void *key, int keylen,
   void *out, int outlen)
{
   BLAKE2B_CTX ctx;

   if (blake2b_init(&ctx, key, keylen, outlen)) {
      return -1;
   }
   blake2b_update(&ctx, in, inlen);
   blake2b_final(&ctx, out);

   return 0;
}  /* end blake2b() */


#endif  /* end _CRYPTO_BLAKE2B_C_ */
