/**
 * sha256.c - SHA256 hash function support
 *
 * Based on Brad Conte's (brad@bradconte.com) basic implementations
 * of cryptography algorithms,
 *    https://github.com/B-Con/crypto-algorithms
 * which was released into the Public Domain and is therefore used
 * with permission, and with much gratitude.  \(^-^)/
 *
 * For more information, please refer to ../LICENSE.UNLICENSE
 *
 * Date: 8 April 2020
 * Revised: 26 October 2021
 *
 * NOTES:
 * - This 32-bit implementation supports 256-bit message digests on
 *   x86 little endian systems, using modified routines and
 *   unrolled loops for faster SHA256 transformations.
 * - This implementation relies on custom datatypes declared within
 *   a custom library. However, in the absense of such a library,
 *   functionality may be reinstated by simply redeclaring
 *   datatypes as appropriate for the target system.
 *
*/

#ifndef _CRYPTO_SHA256_C_
#define _CRYPTO_SHA256_C_  /* include guard */


#include "sha256.h"

static const word32 k[64] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
   0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
   0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
   0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
   0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
   0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* swap bytes of a 32-bit word using an 8-bit word pointer */
static word32 bswap32from8p(const word8 bp[])
{
   return ( ((word32) bp[0] << 24) | ((word32) bp[1] << 16) |
            ((word32) bp[2] << 8) | ((word32) bp[3]) );
}  /* end bswap32from8p() */

/* SHA256 transformation */
static void sha256_transform(SHA256_CTX *ctx, const word8 data[])
{
   word32 a, b, c, d, e, f, g, h, i, t1, t2, m[64];

   /* Since this implementation uses little endian byte ordering and
    * SHA uses big endian, reverse all the bytes upon input, and
    * re-reverse them on output */
   m[0] = bswap32from8p(&data[0]);
   m[1] = bswap32from8p(&data[4]);
   m[2] = bswap32from8p(&data[8]);
   m[3] = bswap32from8p(&data[12]);
   m[4] = bswap32from8p(&data[16]);
   m[5] = bswap32from8p(&data[20]);
   m[6] = bswap32from8p(&data[24]);
   m[7] = bswap32from8p(&data[28]);
   m[8] = bswap32from8p(&data[32]);
   m[9] = bswap32from8p(&data[36]);
   m[10] = bswap32from8p(&data[40]);
   m[11] = bswap32from8p(&data[44]);
   m[12] = bswap32from8p(&data[48]);
   m[13] = bswap32from8p(&data[52]);
   m[14] = bswap32from8p(&data[56]);
   m[15] = bswap32from8p(&data[60]);

   m[16] = SIG1(m[14]) + m[9] + SIG0(m[1]) + m[0];
   m[17] = SIG1(m[15]) + m[10] + SIG0(m[2]) + m[1];
   m[18] = SIG1(m[16]) + m[11] + SIG0(m[3]) + m[2];
   m[19] = SIG1(m[17]) + m[12] + SIG0(m[4]) + m[3];
   m[20] = SIG1(m[18]) + m[13] + SIG0(m[5]) + m[4];
   m[21] = SIG1(m[19]) + m[14] + SIG0(m[6]) + m[5];
   m[22] = SIG1(m[20]) + m[15] + SIG0(m[7]) + m[6];
   m[23] = SIG1(m[21]) + m[16] + SIG0(m[8]) + m[7];
   m[24] = SIG1(m[22]) + m[17] + SIG0(m[9]) + m[8];
   m[25] = SIG1(m[23]) + m[18] + SIG0(m[10]) + m[9];
   m[26] = SIG1(m[24]) + m[19] + SIG0(m[11]) + m[10];
   m[27] = SIG1(m[25]) + m[20] + SIG0(m[12]) + m[11];
   m[28] = SIG1(m[26]) + m[21] + SIG0(m[13]) + m[12];
   m[29] = SIG1(m[27]) + m[22] + SIG0(m[14]) + m[13];
   m[30] = SIG1(m[28]) + m[23] + SIG0(m[15]) + m[14];
   m[31] = SIG1(m[29]) + m[24] + SIG0(m[16]) + m[15];
   m[32] = SIG1(m[30]) + m[25] + SIG0(m[17]) + m[16];
   m[33] = SIG1(m[31]) + m[26] + SIG0(m[18]) + m[17];
   m[34] = SIG1(m[32]) + m[27] + SIG0(m[19]) + m[18];
   m[35] = SIG1(m[33]) + m[28] + SIG0(m[20]) + m[19];
   m[36] = SIG1(m[34]) + m[29] + SIG0(m[21]) + m[20];
   m[37] = SIG1(m[35]) + m[30] + SIG0(m[22]) + m[21];
   m[38] = SIG1(m[36]) + m[31] + SIG0(m[23]) + m[22];
   m[39] = SIG1(m[37]) + m[32] + SIG0(m[24]) + m[23];
   m[40] = SIG1(m[38]) + m[33] + SIG0(m[25]) + m[24];
   m[41] = SIG1(m[39]) + m[34] + SIG0(m[26]) + m[25];
   m[42] = SIG1(m[40]) + m[35] + SIG0(m[27]) + m[26];
   m[43] = SIG1(m[41]) + m[36] + SIG0(m[28]) + m[27];
   m[44] = SIG1(m[42]) + m[37] + SIG0(m[29]) + m[28];
   m[45] = SIG1(m[43]) + m[38] + SIG0(m[30]) + m[29];
   m[46] = SIG1(m[44]) + m[39] + SIG0(m[31]) + m[30];
   m[47] = SIG1(m[45]) + m[40] + SIG0(m[32]) + m[31];
   m[48] = SIG1(m[46]) + m[41] + SIG0(m[33]) + m[32];
   m[49] = SIG1(m[47]) + m[42] + SIG0(m[34]) + m[33];
   m[50] = SIG1(m[48]) + m[43] + SIG0(m[35]) + m[34];
   m[51] = SIG1(m[49]) + m[44] + SIG0(m[36]) + m[35];
   m[52] = SIG1(m[50]) + m[45] + SIG0(m[37]) + m[36];
   m[53] = SIG1(m[51]) + m[46] + SIG0(m[38]) + m[37];
   m[54] = SIG1(m[52]) + m[47] + SIG0(m[39]) + m[38];
   m[55] = SIG1(m[53]) + m[48] + SIG0(m[40]) + m[39];
   m[56] = SIG1(m[54]) + m[49] + SIG0(m[41]) + m[40];
   m[57] = SIG1(m[55]) + m[50] + SIG0(m[42]) + m[41];
   m[58] = SIG1(m[56]) + m[51] + SIG0(m[43]) + m[42];
   m[59] = SIG1(m[57]) + m[52] + SIG0(m[44]) + m[43];
   m[60] = SIG1(m[58]) + m[53] + SIG0(m[45]) + m[44];
   m[61] = SIG1(m[59]) + m[54] + SIG0(m[46]) + m[45];
   m[62] = SIG1(m[60]) + m[55] + SIG0(m[47]) + m[46];
   m[63] = SIG1(m[61]) + m[56] + SIG0(m[48]) + m[47];

   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];
   e = ctx->state[4];
   f = ctx->state[5];
   g = ctx->state[6];
   h = ctx->state[7];

   for (i = 0; i < SHA256ROUNDS; i++) {
      t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
      t2 = EP0(a) + MAJ(a,b,c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
   }

   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
   ctx->state[4] += e;
   ctx->state[5] += f;
   ctx->state[6] += g;
   ctx->state[7] += h;
}  /* end sha256_transform() */

/* Initialize the hashing context `ctx` */
void sha256_init(SHA256_CTX *ctx)
{
   ctx->datalen = 0;
   ctx->bitlen[0] = ctx->bitlen[1] = 0;
   ctx->state[0] = 0x6a09e667;
   ctx->state[1] = 0xbb67ae85;
   ctx->state[2] = 0x3c6ef372;
   ctx->state[3] = 0xa54ff53a;
   ctx->state[4] = 0x510e527f;
   ctx->state[5] = 0x9b05688c;
   ctx->state[6] = 0x1f83d9ab;
   ctx->state[7] = 0x5be0cd19;
}  /* end sha256_init() */

/* Add `inlen` bytes from `in` into the hash */
void sha256_update(SHA256_CTX *ctx, const void *in, size_t inlen)
{
   size_t i;
   word32 old;

   for (i = 0; i < inlen; ++i) {
      ctx->data[ctx->datalen] = ((const word8 *) in)[i];
      ctx->datalen++;
      if (ctx->datalen == 64) {
         sha256_transform(ctx, ctx->data);
         ctx->datalen = 0;
         old = ctx->bitlen[0];
         ctx->bitlen[0] += 512;
         if(ctx->bitlen[0] < old) ctx->bitlen[1]++;  /* add in carry */
      }
   }
}  /* end sha256_update() */

/* Generate the message digest and place in `out` */
void sha256_final(SHA256_CTX *ctx, void *out)
{
   word32 i, old;

   i = ctx->datalen;

   /* Pad whatever data is left in the buffer. */
   if (ctx->datalen < 56) {
      ctx->data[i++] = 0x80;
      while (i < 56) {
         ctx->data[i++] = 0x00;
      }
   } else {
      ctx->data[i++] = 0x80;
      while (i < 64) {
         ctx->data[i++] = 0x00;
      }
      sha256_transform(ctx, ctx->data);
      ((word32 *) ctx->data)[0] = 0;
      ((word32 *) ctx->data)[1] = 0;
      ((word32 *) ctx->data)[2] = 0;
      ((word32 *) ctx->data)[3] = 0;
      ((word32 *) ctx->data)[4] = 0;
      ((word32 *) ctx->data)[5] = 0;
      ((word32 *) ctx->data)[6] = 0;
      ((word32 *) ctx->data)[7] = 0;
      ((word32 *) ctx->data)[8] = 0;
      ((word32 *) ctx->data)[9] = 0;
      ((word32 *) ctx->data)[10] = 0;
      ((word32 *) ctx->data)[11] = 0;
      ((word32 *) ctx->data)[12] = 0;
      ((word32 *) ctx->data)[13] = 0;
   }

   /* Append to the padding the total message's length in bits and
    * transform (big endian). */
   old = ctx->bitlen[0];
   ctx->bitlen[0] += ctx->datalen << 3;
   if(ctx->bitlen[0] < old) ctx->bitlen[1]++;  /* add in carry */
   /* immitate bswap64() for bitlen */
   ((word32 *) ctx->data)[15] = bswap32from8p((word8 *) &ctx->bitlen[0]);
   ((word32 *) ctx->data)[14] = bswap32from8p((word8 *) &ctx->bitlen[1]);
   sha256_transform(ctx, ctx->data);

   /* Since this implementation uses little endian byte ordering and
    * SHA uses big endian, reverse all the bytes when copying the
    * final state to the output hash. */
   ((word32 *) out)[0] = bswap32from8p((word8 *) &ctx->state[0]);
   ((word32 *) out)[1] = bswap32from8p((word8 *) &ctx->state[1]);
   ((word32 *) out)[2] = bswap32from8p((word8 *) &ctx->state[2]);
   ((word32 *) out)[3] = bswap32from8p((word8 *) &ctx->state[3]);
   ((word32 *) out)[4] = bswap32from8p((word8 *) &ctx->state[4]);
   ((word32 *) out)[5] = bswap32from8p((word8 *) &ctx->state[5]);
   ((word32 *) out)[6] = bswap32from8p((word8 *) &ctx->state[6]);
   ((word32 *) out)[7] = bswap32from8p((word8 *) &ctx->state[7]);
}  /* end sha256_final() */

/* Convenient all-in-one SHA256 computation */
void sha256(const void *in, size_t inlen, void *out)
{
   SHA256_CTX ctx;

   sha256_init(&ctx);
   sha256_update(&ctx, in, inlen);
   sha256_final(&ctx, out);
}  /* end sha256() */


#endif  /* end _CRYPTO_SHA256_C_ */
