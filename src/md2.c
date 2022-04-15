/**
 * @private
 * @headerfile md2.h <md2.h>
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

/* include guard */
#ifndef CRYPTO_MD2_C
#define CRYPTO_MD2_C


#include "md2.h"
#include <string.h>  /* for memory handling */

/**
 * @private
 * MD2 transformation rounds.
 * @param ctx Pointer to MD2 context
 * @param data Pointer to input to be transformed
*/
void md2_transform(MD2_CTX *ctx, uint8_t data[])
{
   /**
    * @private
    * MD2 transformation constant.
   */
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
   };  /* end static const uint8_t s[256] */

   int j, k;

   memcpy(ctx->state + 16, data, 16);
   ((uint64_t *) ctx->state)[4] = \
      (((uint64_t *) ctx->state)[2] ^ ((uint64_t *) ctx->state)[0]);
   ((uint64_t *) ctx->state)[5] = \
      (((uint64_t *) ctx->state)[3] ^ ((uint64_t *) ctx->state)[1]);

	ctx->state[0] ^= s[0];
   for (k = 1; k < 48; ++k) {
		ctx->state[k] ^= s[ctx->state[k - 1]];
	}
	for (j = 1; j < 18; ++j) {
      ctx->state[0] ^= s[(ctx->state[47] + (j - 1)) & 0xFF];
      for (k = 1; k < 48; ++k) {
         ctx->state[k] ^= s[ctx->state[k - 1]];
      }
	}

   ctx->checksum[0] ^= s[data[0] ^ ctx->checksum[15]];
	for (j = 1; j < 16; ++j) {
		ctx->checksum[j] ^= s[data[j] ^ ctx->checksum[j - 1]];
	}
}  /* md2_transform() */

/**
 * Initialize a MD2 context.
 * @param ctx Pointer to MD2 context
*/
void md2_init(MD2_CTX *ctx)
{
   memset(ctx->state, 0, 48);
   memset(ctx->checksum, 0, 16);
   ctx->datalen = 0;
}  /* end md2_init() */

/**
 * Add @a inlen bytes from @a in to a MD2 context for hashing.
 * @param ctx Pointer to MD2 context
 * @param in Pointer to data to hash
 * @param inlen Length of @a in data, in bytes
*/
void md2_update(MD2_CTX *ctx, const void *in, size_t inlen)
{
   size_t i, n;

   for(i = n = 0; inlen; i += n, inlen -= n) {
      /* copy memory to input buffer in chunks */
      n = (ctx->datalen + inlen) > 16 ? 16 - ctx->datalen : inlen;
      memcpy(ctx->data + ctx->datalen, (const uint8_t *) in + i, n);
      ctx->datalen += n;
      /* process input buffer */
      if (ctx->datalen == 16) {
         md2_transform(ctx, ctx->data);
         ctx->datalen = 0;
      }
   }
}  /* md2_update() */

/**
 * Finalize a MD2 message digest.
 * Generate the MD2 message digest and place in @a out.
 * @param ctx Pointer to MD2 context
 * @param out Pointer to location to place the message digest
*/
void md2_final(MD2_CTX *ctx, void *out)
{
   size_t to_pad;

   /* pad remaining input buffer */
   to_pad = 16 - ctx->datalen;
   memset(ctx->data + ctx->datalen, (int) to_pad, to_pad);

   /* perform final transform */
   md2_transform(ctx, ctx->data);
   md2_transform(ctx, ctx->checksum);

   /* copy digest to out */
   memcpy(out, ctx->state, MD2LEN);
}  /* md2_final() */

/**
 * Convenient all-in-one MD2 computation.
 * Performs md2_init(), md2_update() and md2_final(),
 * and places the resulting hash in @a out.
 * @param in Pointer to data to hash
 * @param inlen Length of @a in data, in bytes
 * @param out Pointer to location to place the message digest
*/
void md2(const void *in, size_t inlen, void *out)
{
   MD2_CTX ctx;

   md2_init(&ctx);
   md2_update(&ctx, in, inlen);
   md2_final(&ctx, out);
}  /* md2() */

/* end include guard */
#endif
