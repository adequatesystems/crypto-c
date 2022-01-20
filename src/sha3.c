/**
 * sha3.c - SHA3 and Keccak hash function support
 *
 * Based on Dr. Markku-Juhani O. Saarinen's (mjos@iki.fi)
 * "cooked up" compact and readable keccak implemetation,
 *    <https://github.com/mjosaarinen/tiny_sha3>
 * which was released under the MIT license (MIT) and is therefore
 * used with permission, and with much gratitude.  \(^-^)/
 *
 * Original works Copyright (c) 2015 Markku-Juhani O. Saarinen
 * Modified works Copyright (c) 2020-2021 Adequate Systems, LLC.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * For more information, please refer to ../LICENSE.MIT
 *
 * Date: 22 April 2020
 * Revised: 26 October 2021
 *
 * NOTES:
 * - Presently, due to heavy reliance on 64-bit operations, this
 *   implementation CANNOT RUN on systems that rely on C89 compliance.
 * - This implementation supports the SHA-3 and Keccak algorithm
 *   variants for 224, 256, 384 and 512 bit message digests on x86
 *   and x64 little endian systems, using modified routines and
 *   unrolled loops for faster Keccak permutations.
 * - This implementation relies on custom datatypes declared within
 *   a custom library. However, in the absense of such a library,
 *   functionality may be reinstated by simply redeclaring
 *   datatypes as appropriate for the target system.
 *
*/

#ifndef _CRYPTO_SHA3_C_
#define _CRYPTO_SHA3_C_  /* include guard */


#include "sha3.h"

static const word64 keccakf_rndc[24] = {
   0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
   0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
   0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
   0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
   0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
   0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
   0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
   0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

/* SHA3_Keccak permutation */
static void sha3_keccakf(word64 st[])
{
   word64 t, bc[5];
   int r;

   for (r = 0; r < KECCAKFROUNDS; r++) {
      bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
      bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
      bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
      bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
      bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];
      t = bc[4] ^ ROTL64(bc[1], 1);
      st[0] ^= t;
      st[5] ^= t;
      st[10] ^= t;
      st[15] ^= t;
      st[20] ^= t;
      t = bc[0] ^ ROTL64(bc[2], 1);
      st[1] ^= t;
      st[6] ^= t;
      st[11] ^= t;
      st[16] ^= t;
      st[21] ^= t;
      t = bc[1] ^ ROTL64(bc[3], 1);
      st[2] ^= t;
      st[7] ^= t;
      st[12] ^= t;
      st[17] ^= t;
      st[22] ^= t;
      t = bc[2] ^ ROTL64(bc[4], 1);
      st[3] ^= t;
      st[8] ^= t;
      st[13] ^= t;
      st[18] ^= t;
      st[23] ^= t;
      t = bc[3] ^ ROTL64(bc[0], 1);
      st[4] ^= t;
      st[9] ^= t;
      st[14] ^= t;
      st[19] ^= t;
      st[24] ^= t;
      t = st[1];
      st[1]  = ROTL64(st[6],  44);
      st[6]  = ROTL64(st[9],  20);
      st[9]  = ROTL64(st[22], 61);
      st[22] = ROTL64(st[14], 39);
      st[14] = ROTL64(st[20], 18);
      st[20] = ROTL64(st[2],  62);
      st[2]  = ROTL64(st[12], 43);
      st[12] = ROTL64(st[13], 25);
      st[13] = ROTL64(st[19], 8);
      st[19] = ROTL64(st[23], 56);
      st[23] = ROTL64(st[15], 41);
      st[15] = ROTL64(st[4],  27);
      st[4]  = ROTL64(st[24], 14);
      st[24] = ROTL64(st[21], 2);
      st[21] = ROTL64(st[8],  55);
      st[8]  = ROTL64(st[16], 45);
      st[16] = ROTL64(st[5],  36);
      st[5]  = ROTL64(st[3],  28);
      st[3]  = ROTL64(st[18], 21);
      st[18] = ROTL64(st[17], 15);
      st[17] = ROTL64(st[11], 10);
      st[11] = ROTL64(st[7],  6);
      st[7]  = ROTL64(st[10], 3);
      st[10] = ROTL64(t, 1);
      bc[0] = st[0];
      bc[1] = st[1];
      st[0] ^= (~st[1]) & st[2];
      st[1] ^= (~st[2]) & st[3];
      st[2] ^= (~st[3]) & st[4];
      st[3] ^= (~st[4]) & bc[0];
      st[4] ^= (~bc[0]) & bc[1];
      bc[0] = st[5];
      bc[1] = st[6];
      st[5] ^= (~st[6]) & st[7];
      st[6] ^= (~st[7]) & st[8];
      st[7] ^= (~st[8]) & st[9];
      st[8] ^= (~st[9]) & bc[0];
      st[9] ^= (~bc[0]) & bc[1];
      bc[0] = st[10];
      bc[1] = st[11];
      st[10] ^= (~st[11]) & st[12];
      st[11] ^= (~st[12]) & st[13];
      st[12] ^= (~st[13]) & st[14];
      st[13] ^= (~st[14]) & bc[0];
      st[14] ^= (~bc[0]) & bc[1];
      bc[0] = st[15];
      bc[1] = st[16];
      st[15] ^= (~st[16]) & st[17];
      st[16] ^= (~st[17]) & st[18];
      st[17] ^= (~st[18]) & st[19];
      st[18] ^= (~st[19]) & bc[0];
      st[19] ^= (~bc[0]) & bc[1];
      bc[0] = st[20];
      bc[1] = st[21];
      st[20] ^= (~st[21]) & st[22];
      st[21] ^= (~st[22]) & st[23];
      st[22] ^= (~st[23]) & st[24];
      st[23] ^= (~st[24]) & bc[0];
      st[24] ^= (~bc[0]) & bc[1];
      st[0] ^= keccakf_rndc[r];
   }
}

/* Initialize the hashing context `ctx` */
void sha3_init(SHA3_CTX *ctx, int outlen)
{
   int i;

   for (i = 0; i < 25; i++) {
      ctx->st.q[i] = 0;
   }
   ctx->outlen = outlen;
   ctx->rsiz = 200 - (ctx->outlen << 1);
   ctx->pt = 0;
}

/* Add `inlen` bytes from `in` into the hash */
void sha3_update(SHA3_CTX *ctx, const void *in, size_t inlen)
{
   size_t i;
   int j;

   j = ctx->pt;
   for (i = 0; i < inlen; i++) {
      ctx->st.b[j++] ^= ((const word8 *) in)[i];
      if (j >= ctx->rsiz) {
         sha3_keccakf(ctx->st.q);
         j = 0;
      }
   }
   ctx->pt = j;
}

/* Generate the message digest and place in `out` */
void sha3_final(SHA3_CTX *ctx, void *out)
{
   ctx->st.b[ctx->pt] ^= 0x06;
   ctx->st.b[ctx->rsiz - 1] ^= 0x80;
   sha3_keccakf(ctx->st.q);

   /* 224-bit digest */
   ((word64 *) out)[0] = ctx->st.q[0];
   ((word64 *) out)[1] = ctx->st.q[1];
   ((word64 *) out)[2] = ctx->st.q[2];
   ((word32 *) out)[6] = ctx->st.d[6];
   if (ctx->outlen <= 28) return;

   /* 256-bit digest */
   ((word32 *) out)[7] = ctx->st.d[7];
   if (ctx->outlen <= 32) return;

   /* 384-bit digest */
   ((word64 *) out)[4] = ctx->st.q[4];
   ((word64 *) out)[5] = ctx->st.q[5];
   if (ctx->outlen <= 48) return;

   /* 512-bit digest */
   ((word64 *) out)[6] = ctx->st.q[6];
   ((word64 *) out)[7] = ctx->st.q[7];
}
void keccak_final(SHA3_CTX *ctx, void *out)
{
   /* This next step essentially converts the sha3_final() step
    * `c->st.b[c->pt] ^= 0x06;`  (to)  `c->st.b[c->pt] ^= 0x01;`
    * as per the original Keccak implementation. */
   ctx->st.b[ctx->pt] ^= 0x07;
   sha3_final(ctx, out);
}

/* Convenient all-in-one SHA3 computation */
void sha3(const void *in, size_t inlen, void *out, int outlen)
{
   SHA3_CTX sha3;

   sha3_init(&sha3, outlen);
   sha3_update(&sha3, in, inlen);
   sha3_final(&sha3, out);
}

/* Convenient all-in-one Keccak computation */
void keccak(const void *in, size_t inlen, void *out, int outlen)
{
   KECCAK_CTX keccak;

   keccak_init(&keccak, outlen);
   keccak_update(&keccak, in, inlen);
   keccak_final(&keccak, out);
}


#endif  /* end _CRYPTO_SHA3_C_ */
