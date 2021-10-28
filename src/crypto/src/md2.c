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
 * Revised: 26 October 2021
 *
 * NOTES:
 * - This 32-bit implementation supports 128-bit message digests on
 *   x86 little endian systems, using modified routines and
 *   unrolled loops for faster MD2 transformations.
 * - This implementation relies on custom datatypes declared within
 *   a custom library. However, in the absense of such a library,
 *   functionality may be reinstated by simply redeclaring
 *   datatypes as appropriate for the target system.
 *
*/

#ifndef _CRYPTO_MD2_C_
#define _CRYPTO_MD2_C_  /* include guard */


#include "md2.h"

/* Unrolled dependency chain within md2_transform() */
#define md2_transform_round(i, s, state)  \
   state[0] ^= s[( i )]; state[1] ^= s[state[0]];   \
   state[2] ^= s[state[1]]; state[3] ^= s[state[2]];   \
   state[4] ^= s[state[3]]; state[5] ^= s[state[4]];   \
   state[6] ^= s[state[5]]; state[7] ^= s[state[6]];   \
   state[8] ^= s[state[7]]; state[9] ^= s[state[8]];   \
   state[10] ^= s[state[9]]; state[11] ^= s[state[10]]; \
   state[12] ^= s[state[11]]; state[13] ^= s[state[12]]; \
   state[14] ^= s[state[13]]; state[15] ^= s[state[14]]; \
   state[16] ^= s[state[15]]; state[17] ^= s[state[16]]; \
   state[18] ^= s[state[17]]; state[19] ^= s[state[18]]; \
   state[20] ^= s[state[19]]; state[21] ^= s[state[20]]; \
   state[22] ^= s[state[21]]; state[23] ^= s[state[22]]; \
   state[24] ^= s[state[23]]; state[25] ^= s[state[24]]; \
   state[26] ^= s[state[25]]; state[27] ^= s[state[26]]; \
   state[28] ^= s[state[27]]; state[29] ^= s[state[28]]; \
   state[30] ^= s[state[29]]; state[31] ^= s[state[30]]; \
   state[32] ^= s[state[31]]; state[33] ^= s[state[32]]; \
   state[34] ^= s[state[33]]; state[35] ^= s[state[34]]; \
   state[36] ^= s[state[35]]; state[37] ^= s[state[36]]; \
   state[38] ^= s[state[37]]; state[39] ^= s[state[38]]; \
   state[40] ^= s[state[39]]; state[41] ^= s[state[40]]; \
   state[42] ^= s[state[41]]; state[43] ^= s[state[42]]; \
   state[44] ^= s[state[43]]; state[45] ^= s[state[44]]; \
   state[46] ^= s[state[45]]; state[47] ^= s[state[46]];

static const word8 s[256] = {
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
};  /* end static const word8 s[256] */

/* MD2 transformation */
void md2_transform(MD2_CTX *ctx, word8 data[])
{
   ((word32 *) ctx->state)[4] = ((word32 *) data)[0];
   ((word32 *) ctx->state)[5] = ((word32 *) data)[1];
   ((word32 *) ctx->state)[6] = ((word32 *) data)[2];
   ((word32 *) ctx->state)[7] = ((word32 *) data)[3];
   ((word32 *) ctx->state)[8] = \
      (((word32 *) ctx->state)[4] ^ ((word32 *) ctx->state)[0]);
   ((word32 *) ctx->state)[9] = \
      (((word32 *) ctx->state)[5] ^ ((word32 *) ctx->state)[1]);
   ((word32 *) ctx->state)[10] = \
      (((word32 *) ctx->state)[6] ^ ((word32 *) ctx->state)[2]);
   ((word32 *) ctx->state)[11] = \
      (((word32 *) ctx->state)[7] ^ ((word32 *) ctx->state)[3]);

   md2_transform_round(0, s, ctx->state);
   md2_transform_round((word8) (ctx->state[47]), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 1), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 2), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 3), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 4), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 5), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 6), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 7), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 8), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 9), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 10), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 11), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 12), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 13), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 14), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 15), s, ctx->state);
   md2_transform_round((word8) (ctx->state[47] + 16), s, ctx->state);

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
}  /* md2_transform() */

/* Initialize the hashing context `ctx` */
void md2_init(MD2_CTX *ctx)
{
   ((word32 *) ctx->state)[0] = 0;
   ((word32 *) ctx->state)[1] = 0;
   ((word32 *) ctx->state)[2] = 0;
   ((word32 *) ctx->state)[3] = 0;
   ((word32 *) ctx->state)[4] = 0;
   ((word32 *) ctx->state)[5] = 0;
   ((word32 *) ctx->state)[6] = 0;
   ((word32 *) ctx->state)[7] = 0;
   ((word32 *) ctx->state)[8] = 0;
   ((word32 *) ctx->state)[9] = 0;
   ((word32 *) ctx->state)[10] = 0;
   ((word32 *) ctx->state)[11] = 0;
   ((word32 *) ctx->checksum)[0] = 0;
   ((word32 *) ctx->checksum)[1] = 0;
   ((word32 *) ctx->checksum)[2] = 0;
   ((word32 *) ctx->checksum)[3] = 0;
   ctx->len = 0;
}  /* md2_init() */

/* Add `inlen` bytes from `in` into the hash */
void md2_update(MD2_CTX *ctx, const void *in, size_t inlen)
{
   size_t i;

   for (i = 0; i < inlen; ++i) {
      ctx->data[ctx->len] = ((const word8 *) in)[i];
      ctx->len++;
      if (ctx->len == 16) {
         md2_transform(ctx, ctx->data);
         ctx->len = 0;
      }
   }
}  /* md2_update() */

/* Generate the message digest and place in `out` */
void md2_final(MD2_CTX *ctx, void *out)
{
   word32 to_pad;

   to_pad = 16 - ctx->len;

   while(ctx->len < 16) {
      ctx->data[ctx->len++] = (word8) to_pad;
   }

   md2_transform(ctx, ctx->data);
   md2_transform(ctx, ctx->checksum);

   ((word32 *) out)[0] = ((word32 *) ctx->state)[0];
   ((word32 *) out)[1] = ((word32 *) ctx->state)[1];
   ((word32 *) out)[2] = ((word32 *) ctx->state)[2];
   ((word32 *) out)[3] = ((word32 *) ctx->state)[3];
}  /* md2_final() */

/* Convenient all-in-one MD2 computation */
void md2(const void *in, size_t inlen, void *out)
{
   MD2_CTX ctx;

   md2_init(&ctx);
   md2_update(&ctx, in, inlen);
   md2_final(&ctx, out);
}  /* md2() */


#endif  /* end _CRYPTO_MD2_C_ */
