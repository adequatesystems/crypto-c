/**
 * md2.c - MD2 hash function support
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
 * NOTE: This implementation supports MD2 message digests on x86_64
 * little endian hardware, using modified routines for faster MD2
 * transformations.
 *
*/

#ifndef _MD2_C_
#define _MD2_C_  /* include guard */


#include "md2.h"

/* MD2 transformation */
void md2_transform(MD2_CTX *ctx, uint8_t data[])
{
   static const uint8_t s[256] = {
      41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
      19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
      76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
      138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
      245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
      148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
      39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
      181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
      150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
      112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
      96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
      85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
      234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
      129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
      8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
      203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
      166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
      31, 26, 219, 153, 141, 51, 159, 17, 131, 20
   };
   int i;

   ((uint64_t *) ctx->state)[2] = ((uint64_t *) data)[0];
   ((uint64_t *) ctx->state)[3] = ((uint64_t *) data)[1];
   ((uint64_t *) ctx->state)[4] = \
      (((uint64_t *) ctx->state)[2] ^ ((uint64_t *) ctx->state)[0]);
   ((uint64_t *) ctx->state)[5] = \
      (((uint64_t *) ctx->state)[3] ^ ((uint64_t *) ctx->state)[1]);

   md2_transform_round(0);
   for (i = 0; i < 17; i++) {
      md2_transform_round((ctx->state[47] + i) & 0xff);
   }

   ctx->checksum[0] ^= s[data[0] ^ ctx->checksum[15]];
   ctx->checksum[1] ^= s[data[1] ^ ctx->checksum[0]];
   ctx->checksum[2] ^= s[data[2] ^ ctx->checksum[1]];
   ctx->checksum[3] ^= s[data[3] ^ ctx->checksum[2]];
   ctx->checksum[4] ^= s[data[4] ^ ctx->checksum[3]];
   ctx->checksum[5] ^= s[data[5] ^ ctx->checksum[4]];
   ctx->checksum[6] ^= s[data[6] ^ ctx->checksum[5]];
   ctx->checksum[7] ^= s[data[7] ^ ctx->checksum[6]];
   ctx->checksum[8] ^= s[data[8] ^ ctx->checksum[7]];
   ctx->checksum[9] ^= s[data[9] ^ ctx->checksum[8]];
   ctx->checksum[10] ^= s[data[10] ^ ctx->checksum[9]];
   ctx->checksum[11] ^= s[data[11] ^ ctx->checksum[10]];
   ctx->checksum[12] ^= s[data[12] ^ ctx->checksum[11]];
   ctx->checksum[13] ^= s[data[13] ^ ctx->checksum[12]];
   ctx->checksum[14] ^= s[data[14] ^ ctx->checksum[13]];
   ctx->checksum[15] ^= s[data[15] ^ ctx->checksum[14]];
}

/* Initialize the hashing context `ctx` */
void md2_init(MD2_CTX *ctx)
{
   ((uint64_t *) ctx->state)[0] = 0;
   ((uint64_t *) ctx->state)[1] = 0;
   ((uint64_t *) ctx->state)[2] = 0;
   ((uint64_t *) ctx->state)[3] = 0;
   ((uint64_t *) ctx->state)[4] = 0;
   ((uint64_t *) ctx->state)[5] = 0;
   ((uint64_t *) ctx->checksum)[0] = 0;
   ((uint64_t *) ctx->checksum)[1] = 0;
   ctx->len = 0;
}

/* Add `inlen` bytes from `in` into the hash */
void md2_update(MD2_CTX *ctx, const void *in, size_t inlen)
{
   size_t i;

   for (i = 0; i < inlen; ++i) {
      ctx->data[ctx->len] = ((const uint8_t *) in)[i];
      ctx->len++;
      if (ctx->len == 16) {
         md2_transform(ctx, ctx->data);
         ctx->len = 0;
      }
   }
}

/* Generate the message digest and place in `out` */
void md2_final(MD2_CTX *ctx, void *out)
{
   uint32_t to_pad;

   to_pad = 16 - ctx->len;

   while(ctx->len < 16) {
      ctx->data[ctx->len++] = (uint8_t) to_pad;
   }

   md2_transform(ctx, ctx->data);
   md2_transform(ctx, ctx->checksum);

   ((uint64_t *) out)[0] = ((uint64_t *) ctx->state)[0];
   ((uint64_t *) out)[1] = ((uint64_t *) ctx->state)[1];
}

/* Convenient all-in-one MD2 computation */
void md2(const void *in, size_t inlen, void *out)
{
   MD2_CTX ctx;

   md2_init(&ctx);
   md2_update(&ctx, in, inlen);
   md2_final(&ctx, out);
}


#endif  /* end _MD2_C_ */
