/**
 * sha256.c - SHA256 hash function support
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
 * Revised: 19 August 2021
 *
 * NOTE: This implementation supports SHA256 message digests on x86_64
 * little endian hardware, using modified routines for faster SHA256
 * transformations.
 *
*/

#ifndef _SHA256_C_
#define _SHA256_C_  /* include guard */


#include "sha256.h"

/* SHA256 transformation */
void sha256_transform(SHA256_CTX *ctx, const uint8_t data[])
{
   static const uint32_t k[64] = {
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
   uint32_t a, b, c, d, e, f, g, h, i, t1, t2, m[64];

   /* Since this implementation uses little endian byte ordering and
    * SHA uses big endian, reverse all the bytes upon input, and
    * re-reverse them on output */
   m[0] = ((uint32_t) data[0] << 24) + ((uint32_t) data[1] << 16) +
          ((uint32_t) data[2] << 8) + ((uint32_t) data[3]);
   m[1] = ((uint32_t) data[4] << 24) + ((uint32_t) data[5] << 16) +
          ((uint32_t) data[6] << 8) + ((uint32_t) data[7]);
   m[2] = ((uint32_t) data[8] << 24) + ((uint32_t) data[9] << 16) +
          ((uint32_t) data[10] << 8) + ((uint32_t) data[11]);
   m[3] = ((uint32_t) data[12] << 24) + ((uint32_t) data[13] << 16) +
          ((uint32_t) data[14] << 8) + ((uint32_t) data[15]);
   m[4] = ((uint32_t) data[16] << 24) + ((uint32_t) data[17] << 16) +
          ((uint32_t) data[18] << 8) + ((uint32_t) data[19]);
   m[5] = ((uint32_t) data[20] << 24) + ((uint32_t) data[21] << 16) +
          ((uint32_t) data[22] << 8) + ((uint32_t) data[23]);
   m[6] = ((uint32_t) data[24] << 24) + ((uint32_t) data[25] << 16) +
          ((uint32_t) data[26] << 8) + ((uint32_t) data[27]);
   m[7] = ((uint32_t) data[28] << 24) + ((uint32_t) data[29] << 16) +
          ((uint32_t) data[30] << 8) + ((uint32_t) data[31]);
   m[8] = ((uint32_t) data[32] << 24) + ((uint32_t) data[33] << 16) +
          ((uint32_t) data[34] << 8) + ((uint32_t) data[35]);
   m[9] = ((uint32_t) data[36] << 24) + ((uint32_t) data[37] << 16) +
          ((uint32_t) data[38] << 8) + ((uint32_t) data[39]);
   m[10] = ((uint32_t) data[40] << 24) + ((uint32_t) data[41] << 16) +
           ((uint32_t) data[42] << 8) + ((uint32_t) data[43]);
   m[11] = ((uint32_t) data[44] << 24) + ((uint32_t) data[45] << 16) +
           ((uint32_t) data[46] << 8) + ((uint32_t) data[47]);
   m[12] = ((uint32_t) data[48] << 24) + ((uint32_t) data[49] << 16) +
           ((uint32_t) data[50] << 8) + ((uint32_t) data[51]);
   m[13] = ((uint32_t) data[52] << 24) + ((uint32_t) data[53] << 16) +
           ((uint32_t) data[54] << 8) + ((uint32_t) data[55]);
   m[14] = ((uint32_t) data[56] << 24) + ((uint32_t) data[57] << 16) +
           ((uint32_t) data[58] << 8) + ((uint32_t) data[59]);
   m[15] = ((uint32_t) data[60] << 24) + ((uint32_t) data[61] << 16) +
           ((uint32_t) data[62] << 8) + ((uint32_t) data[63]);

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

   for (i = 0; i < SHA256_ROUNDS; i++) {
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
}

/* Initialize the hashing context `ctx` */
void sha256_init(SHA256_CTX *ctx)
{
   ctx->datalen = 0;
   ctx->bitlen = 0;
   ctx->state[0] = 0x6a09e667;
   ctx->state[1] = 0xbb67ae85;
   ctx->state[2] = 0x3c6ef372;
   ctx->state[3] = 0xa54ff53a;
   ctx->state[4] = 0x510e527f;
   ctx->state[5] = 0x9b05688c;
   ctx->state[6] = 0x1f83d9ab;
   ctx->state[7] = 0x5be0cd19;
}

/* Add `inlen` bytes from `in` into the hash */
void sha256_update(SHA256_CTX *ctx, const void *in, size_t inlen)
{
   size_t i;

   for (i = 0; i < inlen; ++i) {
      ctx->data[ctx->datalen] = ((const uint8_t *) in)[i];
      ctx->datalen++;
      if (ctx->datalen == 64) {
         sha256_transform(ctx, ctx->data);
         ctx->bitlen += 512;
         ctx->datalen = 0;
      }
   }
}

/* Generate the message digest and place in `out` */
void sha256_final(SHA256_CTX *ctx, void *out)
{
   uint32_t i;

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
      memset(ctx->data, 0, 56);
   }

   /* Append to the padding the total message's length in bits and
    * transform (big endian). */
   ctx->bitlen += ctx->datalen << 3;
   ctx->data[63] = (uint8_t) (ctx->bitlen);
   ctx->data[62] = (uint8_t) (ctx->bitlen >> 8);
   ctx->data[61] = (uint8_t) (ctx->bitlen >> 16);
   ctx->data[60] = (uint8_t) (ctx->bitlen >> 24);
   ctx->data[59] = (uint8_t) (ctx->bitlen >> 32);
   ctx->data[58] = (uint8_t) (ctx->bitlen >> 40);
   ctx->data[57] = (uint8_t) (ctx->bitlen >> 48);
   ctx->data[56] = (uint8_t) (ctx->bitlen >> 56);
   sha256_transform(ctx, ctx->data);

   /* Since this implementation uses little endian byte ordering and
    * SHA uses big endian, reverse all the bytes when copying the
    * final state to the output hash. */
   ((uint8_t *) out)[0] = (ctx->state[0] >> 24) & 0x000000ff;
   ((uint8_t *) out)[1] = (ctx->state[0] >> 16) & 0x000000ff;
   ((uint8_t *) out)[2] = (ctx->state[0] >> 8) & 0x000000ff;
   ((uint8_t *) out)[3] = (ctx->state[0]) & 0x000000ff;
   ((uint8_t *) out)[4] = (ctx->state[1] >> 24) & 0x000000ff;
   ((uint8_t *) out)[5] = (ctx->state[1] >> 16) & 0x000000ff;
   ((uint8_t *) out)[6] = (ctx->state[1] >> 8) & 0x000000ff;
   ((uint8_t *) out)[7] = (ctx->state[1]) & 0x000000ff;
   ((uint8_t *) out)[8] = (ctx->state[2] >> 24) & 0x000000ff;
   ((uint8_t *) out)[9] = (ctx->state[2] >> 16) & 0x000000ff;
   ((uint8_t *) out)[10] = (ctx->state[2] >> 8) & 0x000000ff;
   ((uint8_t *) out)[11] = (ctx->state[2]) & 0x000000ff;
   ((uint8_t *) out)[12] = (ctx->state[3] >> 24) & 0x000000ff;
   ((uint8_t *) out)[13] = (ctx->state[3] >> 16) & 0x000000ff;
   ((uint8_t *) out)[14] = (ctx->state[3] >> 8) & 0x000000ff;
   ((uint8_t *) out)[15] = (ctx->state[3]) & 0x000000ff;
   ((uint8_t *) out)[16] = (ctx->state[4] >> 24) & 0x000000ff;
   ((uint8_t *) out)[17] = (ctx->state[4] >> 16) & 0x000000ff;
   ((uint8_t *) out)[18] = (ctx->state[4] >> 8) & 0x000000ff;
   ((uint8_t *) out)[19] = (ctx->state[4]) & 0x000000ff;
   ((uint8_t *) out)[20] = (ctx->state[5] >> 24) & 0x000000ff;
   ((uint8_t *) out)[21] = (ctx->state[5] >> 16) & 0x000000ff;
   ((uint8_t *) out)[22] = (ctx->state[5] >> 8) & 0x000000ff;
   ((uint8_t *) out)[23] = (ctx->state[5]) & 0x000000ff;
   ((uint8_t *) out)[24] = (ctx->state[6] >> 24) & 0x000000ff;
   ((uint8_t *) out)[25] = (ctx->state[6] >> 16) & 0x000000ff;
   ((uint8_t *) out)[26] = (ctx->state[6] >> 8) & 0x000000ff;
   ((uint8_t *) out)[27] = (ctx->state[6]) & 0x000000ff;
   ((uint8_t *) out)[28] = (ctx->state[7] >> 24) & 0x000000ff;
   ((uint8_t *) out)[29] = (ctx->state[7] >> 16) & 0x000000ff;
   ((uint8_t *) out)[30] = (ctx->state[7] >> 8) & 0x000000ff;
   ((uint8_t *) out)[31] = (ctx->state[7]) & 0x000000ff;
}

/* Convenient all-in-one SHA256 computation */
void sha256(const void *in, size_t inlen, void *out)
{
   SHA256_CTX ctx;

   sha256_init(&ctx);
   sha256_update(&ctx, in, inlen);
   sha256_final(&ctx, out);
}


#endif  /* end _SHA256_C_ */
