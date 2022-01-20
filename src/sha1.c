/**
 * sha1.c - SHA1 hash function support
 *
 * Based on Brad Conte's (brad@bradconte.com) basic implementations
 * of cryptography algorithms,
 *    <https://github.com/B-Con/crypto-algorithms>
 * which was released into the Public Domain and is therefore used
 * with permission, and with much gratitude.  \(^-^)/
 *
 * For more information, please refer to ../LICENSE.UNLICENSE
 *
 * Date: 8 April 2020
 * Revised: 26 October 2021
 *
 * NOTES:
 * - This 32-bit implementation supports SHA1 message digests on x86
 *   little endian systems, using modified routines and unrolled
 *   loops for faster SHA1 transformations.
 * - This implementation relies on custom datatypes declared within
 *   a custom library. However, in the absense of such a library,
 *   functionality may be reinstated by simply redeclaring
 *   datatypes as appropriate for the target system.
 *
*/

#ifndef _CRYPTO_SHA1_C_
#define _CRYPTO_SHA1_C_  /* include guard */


#include "sha1.h"

/* swap bytes of a 32-bit word using an 8-bit word pointer */
static word32 bswap32from8p(const word8 bp[])
{
   return ( ((word32) bp[0] << 24) | ((word32) bp[1] << 16) |
            ((word32) bp[2] << 8) | ((word32) bp[3]) );
}  /* end bswap32from8p() */

/* SHA1 transformation */
void sha1_transform(SHA1_CTX *ctx, const word8 data[])
{
   static word32 k[4] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };
   word32 a, b, c, d, e, i, t, m[80];

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

   m[16] = (m[13] ^ m[8] ^ m[2] ^ m[0]);
   m[16] = (m[16] << 1) | (m[16] >> 31);
   m[17] = (m[14] ^ m[9] ^ m[3] ^ m[1]);
   m[17] = (m[17] << 1) | (m[17] >> 31);
   m[18] = (m[15] ^ m[10] ^ m[4] ^ m[2]);
   m[18] = (m[18] << 1) | (m[18] >> 31);
   m[19] = (m[16] ^ m[11] ^ m[5] ^ m[3]);
   m[19] = (m[19] << 1) | (m[19] >> 31);
   m[20] = (m[17] ^ m[12] ^ m[6] ^ m[4]);
   m[20] = (m[20] << 1) | (m[20] >> 31);
   m[21] = (m[18] ^ m[13] ^ m[7] ^ m[5]);
   m[21] = (m[21] << 1) | (m[21] >> 31);
   m[22] = (m[19] ^ m[14] ^ m[8] ^ m[6]);
   m[22] = (m[22] << 1) | (m[22] >> 31);
   m[23] = (m[20] ^ m[15] ^ m[9] ^ m[7]);
   m[23] = (m[23] << 1) | (m[23] >> 31);
   m[24] = (m[21] ^ m[16] ^ m[10] ^ m[8]);
   m[24] = (m[24] << 1) | (m[24] >> 31);
   m[25] = (m[22] ^ m[17] ^ m[11] ^ m[9]);
   m[25] = (m[25] << 1) | (m[25] >> 31);
   m[26] = (m[23] ^ m[18] ^ m[12] ^ m[10]);
   m[26] = (m[26] << 1) | (m[26] >> 31);
   m[27] = (m[24] ^ m[19] ^ m[13] ^ m[11]);
   m[27] = (m[27] << 1) | (m[27] >> 31);
   m[28] = (m[25] ^ m[20] ^ m[14] ^ m[12]);
   m[28] = (m[28] << 1) | (m[28] >> 31);
   m[29] = (m[26] ^ m[21] ^ m[15] ^ m[13]);
   m[29] = (m[29] << 1) | (m[29] >> 31);
   m[30] = (m[27] ^ m[22] ^ m[16] ^ m[14]);
   m[30] = (m[30] << 1) | (m[30] >> 31);
   m[31] = (m[28] ^ m[23] ^ m[17] ^ m[15]);
   m[31] = (m[31] << 1) | (m[31] >> 31);
   m[32] = (m[29] ^ m[24] ^ m[18] ^ m[16]);
   m[32] = (m[32] << 1) | (m[32] >> 31);
   m[33] = (m[30] ^ m[25] ^ m[19] ^ m[17]);
   m[33] = (m[33] << 1) | (m[33] >> 31);
   m[34] = (m[31] ^ m[26] ^ m[20] ^ m[18]);
   m[34] = (m[34] << 1) | (m[34] >> 31);
   m[35] = (m[32] ^ m[27] ^ m[21] ^ m[19]);
   m[35] = (m[35] << 1) | (m[35] >> 31);
   m[36] = (m[33] ^ m[28] ^ m[22] ^ m[20]);
   m[36] = (m[36] << 1) | (m[36] >> 31);
   m[37] = (m[34] ^ m[29] ^ m[23] ^ m[21]);
   m[37] = (m[37] << 1) | (m[37] >> 31);
   m[38] = (m[35] ^ m[30] ^ m[24] ^ m[22]);
   m[38] = (m[38] << 1) | (m[38] >> 31);
   m[39] = (m[36] ^ m[31] ^ m[25] ^ m[23]);
   m[39] = (m[39] << 1) | (m[39] >> 31);
   m[40] = (m[37] ^ m[32] ^ m[26] ^ m[24]);
   m[40] = (m[40] << 1) | (m[40] >> 31);
   m[41] = (m[38] ^ m[33] ^ m[27] ^ m[25]);
   m[41] = (m[41] << 1) | (m[41] >> 31);
   m[42] = (m[39] ^ m[34] ^ m[28] ^ m[26]);
   m[42] = (m[42] << 1) | (m[42] >> 31);
   m[43] = (m[40] ^ m[35] ^ m[29] ^ m[27]);
   m[43] = (m[43] << 1) | (m[43] >> 31);
   m[44] = (m[41] ^ m[36] ^ m[30] ^ m[28]);
   m[44] = (m[44] << 1) | (m[44] >> 31);
   m[45] = (m[42] ^ m[37] ^ m[31] ^ m[29]);
   m[45] = (m[45] << 1) | (m[45] >> 31);
   m[46] = (m[43] ^ m[38] ^ m[32] ^ m[30]);
   m[46] = (m[46] << 1) | (m[46] >> 31);
   m[47] = (m[44] ^ m[39] ^ m[33] ^ m[31]);
   m[47] = (m[47] << 1) | (m[47] >> 31);
   m[48] = (m[45] ^ m[40] ^ m[34] ^ m[32]);
   m[48] = (m[48] << 1) | (m[48] >> 31);
   m[49] = (m[46] ^ m[41] ^ m[35] ^ m[33]);
   m[49] = (m[49] << 1) | (m[49] >> 31);
   m[50] = (m[47] ^ m[42] ^ m[36] ^ m[34]);
   m[50] = (m[50] << 1) | (m[50] >> 31);
   m[51] = (m[48] ^ m[43] ^ m[37] ^ m[35]);
   m[51] = (m[51] << 1) | (m[51] >> 31);
   m[52] = (m[49] ^ m[44] ^ m[38] ^ m[36]);
   m[52] = (m[52] << 1) | (m[52] >> 31);
   m[53] = (m[50] ^ m[45] ^ m[39] ^ m[37]);
   m[53] = (m[53] << 1) | (m[53] >> 31);
   m[54] = (m[51] ^ m[46] ^ m[40] ^ m[38]);
   m[54] = (m[54] << 1) | (m[54] >> 31);
   m[55] = (m[52] ^ m[47] ^ m[41] ^ m[39]);
   m[55] = (m[55] << 1) | (m[55] >> 31);
   m[56] = (m[53] ^ m[48] ^ m[42] ^ m[40]);
   m[56] = (m[56] << 1) | (m[56] >> 31);
   m[57] = (m[54] ^ m[49] ^ m[43] ^ m[41]);
   m[57] = (m[57] << 1) | (m[57] >> 31);
   m[58] = (m[55] ^ m[50] ^ m[44] ^ m[42]);
   m[58] = (m[58] << 1) | (m[58] >> 31);
   m[59] = (m[56] ^ m[51] ^ m[45] ^ m[43]);
   m[59] = (m[59] << 1) | (m[59] >> 31);
   m[60] = (m[57] ^ m[52] ^ m[46] ^ m[44]);
   m[60] = (m[60] << 1) | (m[60] >> 31);
   m[61] = (m[58] ^ m[53] ^ m[47] ^ m[45]);
   m[61] = (m[61] << 1) | (m[61] >> 31);
   m[62] = (m[59] ^ m[54] ^ m[48] ^ m[46]);
   m[62] = (m[62] << 1) | (m[62] >> 31);
   m[63] = (m[60] ^ m[55] ^ m[49] ^ m[47]);
   m[63] = (m[63] << 1) | (m[63] >> 31);
   m[64] = (m[61] ^ m[56] ^ m[50] ^ m[48]);
   m[64] = (m[64] << 1) | (m[64] >> 31);
   m[65] = (m[62] ^ m[57] ^ m[51] ^ m[49]);
   m[65] = (m[65] << 1) | (m[65] >> 31);
   m[66] = (m[63] ^ m[58] ^ m[52] ^ m[50]);
   m[66] = (m[66] << 1) | (m[66] >> 31);
   m[67] = (m[64] ^ m[59] ^ m[53] ^ m[51]);
   m[67] = (m[67] << 1) | (m[67] >> 31);
   m[68] = (m[65] ^ m[60] ^ m[54] ^ m[52]);
   m[68] = (m[68] << 1) | (m[68] >> 31);
   m[69] = (m[66] ^ m[61] ^ m[55] ^ m[53]);
   m[69] = (m[69] << 1) | (m[69] >> 31);
   m[70] = (m[67] ^ m[62] ^ m[56] ^ m[54]);
   m[70] = (m[70] << 1) | (m[70] >> 31);
   m[71] = (m[68] ^ m[63] ^ m[57] ^ m[55]);
   m[71] = (m[71] << 1) | (m[71] >> 31);
   m[72] = (m[69] ^ m[64] ^ m[58] ^ m[56]);
   m[72] = (m[72] << 1) | (m[72] >> 31);
   m[73] = (m[70] ^ m[65] ^ m[59] ^ m[57]);
   m[73] = (m[73] << 1) | (m[73] >> 31);
   m[74] = (m[71] ^ m[66] ^ m[60] ^ m[58]);
   m[74] = (m[74] << 1) | (m[74] >> 31);
   m[75] = (m[72] ^ m[67] ^ m[61] ^ m[59]);
   m[75] = (m[75] << 1) | (m[75] >> 31);
   m[76] = (m[73] ^ m[68] ^ m[62] ^ m[60]);
   m[76] = (m[76] << 1) | (m[76] >> 31);
   m[77] = (m[74] ^ m[69] ^ m[63] ^ m[61]);
   m[77] = (m[77] << 1) | (m[77] >> 31);
   m[78] = (m[75] ^ m[70] ^ m[64] ^ m[62]);
   m[78] = (m[78] << 1) | (m[78] >> 31);
   m[79] = (m[76] ^ m[71] ^ m[65] ^ m[63]);
   m[79] = (m[79] << 1) | (m[79] >> 31);

   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];
   e = ctx->state[4];

   i = 0;
   for ( ; i < 20; i++) {
      t = ROTL32(a, 5) + ((b & c) ^ (~b & d)) + e + k[0] + m[i];
      e = d;
      d = c;
      c = ROTL32(b, 30);
      b = a;
      a = t;
   }
   for ( ; i < 40; i++) {
      t = ROTL32(a, 5) + (b ^ c ^ d) + e + k[1] + m[i];
      e = d;
      d = c;
      c = ROTL32(b, 30);
      b = a;
      a = t;
   }
   for ( ; i < 60; i++) {
      t = ROTL32(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + k[2] + m[i];
      e = d;
      d = c;
      c = ROTL32(b, 30);
      b = a;
      a = t;
   }
   for ( ; i < 80; i++) {
      t = ROTL32(a, 5) + (b ^ c ^ d) + e + k[3] + m[i];
      e = d;
      d = c;
      c = ROTL32(b, 30);
      b = a;
      a = t;
   }

   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
   ctx->state[4] += e;
}  /* end sha1_transform() */

/* Initialize the hashing context `ctx` */
void sha1_init(SHA1_CTX *ctx)
{
   ctx->datalen = 0;
   ctx->bitlen[0] = ctx->bitlen[1] = 0;
   ctx->state[0] = 0x67452301;
   ctx->state[1] = 0xEFCDAB89;
   ctx->state[2] = 0x98BADCFE;
   ctx->state[3] = 0x10325476;
   ctx->state[4] = 0xc3d2e1f0;
}  /* end sha1_init() */

/* Add `inlen` bytes from `in` into the hash */
void sha1_update(SHA1_CTX *ctx, const void *in, size_t inlen)
{
   size_t i;
   word32 old;

   for (i = 0; i < inlen; ++i) {
      ctx->data[ctx->datalen] = ((const word8 *) in)[i];
      ctx->datalen++;
      if (ctx->datalen == 64) {
         sha1_transform(ctx, ctx->data);
         ctx->datalen = 0;
         old = ctx->bitlen[0];
         ctx->bitlen[0] += 512;
         if(ctx->bitlen[0] < old) ctx->bitlen[1]++;  /* add in carry */
      }
   }
}  /* end sha1_update() */

/* Generate the message digest and place in `out` */
void sha1_final(SHA1_CTX *ctx, void *out)
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
      sha1_transform(ctx, ctx->data);
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
   ctx->bitlen[0] += (word32) ctx->datalen << 3;
   if(ctx->bitlen[0] < old) ctx->bitlen[1]++;  /* add in carry */
   /* immitate bswap64() for bitlen */
   ((word32 *) ctx->data)[15] = bswap32from8p((word8 *) &ctx->bitlen[0]);
   ((word32 *) ctx->data)[14] = bswap32from8p((word8 *) &ctx->bitlen[1]);
   sha1_transform(ctx, ctx->data);

   /* Since this implementation uses little endian byte ordering and
    * SHA uses big endian, reverse all the bytes when copying the
    * final state to the output hash. */
   ((word32 *) out)[0] = bswap32from8p((word8 *) &ctx->state[0]);
   ((word32 *) out)[1] = bswap32from8p((word8 *) &ctx->state[1]);
   ((word32 *) out)[2] = bswap32from8p((word8 *) &ctx->state[2]);
   ((word32 *) out)[3] = bswap32from8p((word8 *) &ctx->state[3]);
   ((word32 *) out)[4] = bswap32from8p((word8 *) &ctx->state[4]);
   ((word32 *) out)[5] = bswap32from8p((word8 *) &ctx->state[5]);
}  /* end sha1_final() */

/* Convenient all-in-one SHA1 computation */
void sha1(const void *in, size_t inlen, void *out)
{
   SHA1_CTX ctx;

   sha1_init(&ctx);
   sha1_update(&ctx, in, inlen);
   sha1_final(&ctx, out);
}  /* end sha1() */


#endif  /* end _CRYPTO_SHA1_C_ */
