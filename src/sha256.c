/**
 * @private
 * @headerfile sha256.h <sha256.h>
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

/* include guard */
#ifndef CRYPTO_SHA256_C
#define CRYPTO_SHA256_C


#include "sha256.h"
#include <string.h>

/* SHA256 transform routines */

#define EP0(x) xor3(ror32(x, 2), ror32(x, 13), ror32(x, 22))
#define EP1(x) xor3(ror32(x, 6), ror32(x, 11), ror32(x, 25))
#define S0(x)  xor3(ror32(x, 7), ror32(x, 18), ((x) >> 3))
#define S1(x)  xor3(ror32(x, 17), ror32(x, 19), ((x) >> 10))

#define sha256_blk0(i)   ( W[i] = bswap32(W[i]) )
#define sha256_blk(i) \
   ( W[i & 15] += S1(W[(i - 2) & 15]) + W[(i - 7) & 15] + S0(W[(i - 15) & 15]) )

#define Ch(x, y, z)  xandx(x, y, z)
#define Maj(x, y, z) ( (x & y) | (z & (x | y)) )

/* initializer type round */
#define R0(a, b, c, d, e, f, g, h, i) \
   h += EP1(e) + Ch(e,f,g) + k[i] + sha256_blk0(i); \
   d += h; h += EP0(a) + Maj(a, b, c)
/* normal type round */
#define R(a, b, c, d, e, f, g, h, i, j) \
   h += EP1(e) + Ch(e,f,g) + k[i+j] + sha256_blk(i); \
   d += h; h += EP0(a) + Maj(a, b, c)
/* round expansion for initializer type rounds */
#define RX0_8(i) \
  R0(a, b, c, d, e, f, g, h, i); \
  R0(h, a, b, c, d, e, f, g, (i + 1)); \
  R0(g, h, a, b, c, d, e, f, (i + 2)); \
  R0(f, g, h, a, b, c, d, e, (i + 3)); \
  R0(e, f, g, h, a, b, c, d, (i + 4)); \
  R0(d, e, f, g, h, a, b, c, (i + 5)); \
  R0(c, d, e, f, g, h, a, b, (i + 6)); \
  R0(b, c, d, e, f, g, h, a, (i + 7))
/* round expansion for normal type rounds */
#define RX_8(i, j) \
  R(a, b, c, d, e, f, g, h, i, j); \
  R(h, a, b, c, d, e, f, g, (i + 1), j); \
  R(g, h, a, b, c, d, e, f, (i + 2), j); \
  R(f, g, h, a, b, c, d, e, (i + 3), j); \
  R(e, f, g, h, a, b, c, d, (i + 4), j); \
  R(d, e, f, g, h, a, b, c, (i + 5), j); \
  R(c, d, e, f, g, h, a, b, (i + 6), j); \
  R(b, c, d, e, f, g, h, a, (i + 7), j)

/* SHA256 transformation constant */
ALIGN(32) static const uint32_t k[64] = {
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

/**
 * @private
 * SHA256 transformation rounds.
 * @param ctx Pointer to SHA256 context
 * @param data Pointer to input to be transformed
*/
HOST_DEVICE_FN static void sha256_transform(
   SHA256_CTX *ctx, const uint8_t data[])
{
   ALIGN(8) uint32_t W[16];
   uint32_t a, b, c, d, e, f, g, h;

   memcpy(W, data, 64);

   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];
   e = ctx->state[4];
   f = ctx->state[5];
   g = ctx->state[6];
   h = ctx->state[7];

   /* initial 16 rounds */
   RX0_8(0); RX0_8(8);
   /* rounds 16 - 32 */
   RX_8(0, 16); RX_8(8, 16);
   /* rounds 32 - 48 */
   RX_8(0, 32); RX_8(8, 32);
   /* rounds 48 - 64 */
   RX_8(0, 48); RX_8(8, 48);

   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
   ctx->state[4] += e;
   ctx->state[5] += f;
   ctx->state[6] += g;
   ctx->state[7] += h;
}  /* end sha256_transform() */

/**
 * Initialize a SHA256 context.
 * @param ctx Pointer to SHA256 context
*/
HOST_DEVICE_FN void sha256_init(SHA256_CTX *ctx)
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

/**
 * Add @a inlen bytes from @a in to a SHA256 context for hashing.
 * @param ctx Pointer to SHA256 context
 * @param in Pointer to data to hash
 * @param inlen Length of @a in data, in bytes
*/
HOST_DEVICE_FN void sha256_update(SHA256_CTX *ctx, const void *in, size_t inlen)
{
   size_t i, n;
   uint32_t old;

   for(i = n = 0; inlen; i += n, inlen -= n) {
      /* copy memory to input buffer in chunks */
      n = (ctx->datalen + inlen) > 64 ? 64 - ctx->datalen : inlen;
      memcpy(ctx->data + ctx->datalen, (const uint8_t *) in + i, n);
      ctx->datalen += n;
      /* process input buffer */
      if (ctx->datalen == 64) {
         sha256_transform(ctx, ctx->data);
         ctx->datalen = 0;
         old = ctx->bitlen[0];
         ctx->bitlen[0] += 512;
         if (ctx->bitlen[0] < old) ctx->bitlen[1]++;  /* add in carry */
      }
   }
}  /* end sha256_update() */

/**
 * Finalize a SHA256 message digest.
 * Generate the SHA256 message digest and place in @a out.
 * @param ctx Pointer to SHA256 context
 * @param out Pointer to location to place the message digest
*/
HOST_DEVICE_FN void sha256_final(SHA256_CTX *ctx, void *out)
{
   uint32_t i, old;

   i = ctx->datalen;

   /* Pad whatever data is left in the buffer. */
   if (ctx->datalen < 56) {
      ctx->data[i++] = 0x80;
      memset(ctx->data + i, 0, 64 - i);
   } else if (ctx->datalen >= 56) {
      ctx->data[i++] = 0x80;
      if (i < 64) memset(ctx->data + i, 0, 64 - i);
      sha256_transform(ctx, ctx->data);
      memset(ctx->data, 0, 56);
   }

   /* Append to the padding the total message's length in bits and
    * transform (big endian). */
   old = ctx->bitlen[0];
   ctx->bitlen[0] += ctx->datalen << 3;
   if(ctx->bitlen[0] < old) ctx->bitlen[1]++;  /* add in carry */
   /* immitate bswap64() for bitlen */
   ((uint32_t *) ctx->data)[15] = bswap32(ctx->bitlen[0]);
   ((uint32_t *) ctx->data)[14] = bswap32(ctx->bitlen[1]);
   sha256_transform(ctx, ctx->data);

   /* Since this implementation uses little endian byte ordering and
    * SHA uses big endian, reverse all the bytes when copying the
    * final state to the output hash. */
   ((uint32_t *) out)[0] = bswap32(ctx->state[0]);
   ((uint32_t *) out)[1] = bswap32(ctx->state[1]);
   ((uint32_t *) out)[2] = bswap32(ctx->state[2]);
   ((uint32_t *) out)[3] = bswap32(ctx->state[3]);
   ((uint32_t *) out)[4] = bswap32(ctx->state[4]);
   ((uint32_t *) out)[5] = bswap32(ctx->state[5]);
   ((uint32_t *) out)[6] = bswap32(ctx->state[6]);
   ((uint32_t *) out)[7] = bswap32(ctx->state[7]);
}  /* end sha256_final() */

/**
 * Convenient all-in-one SHA256 computation.
 * Performs sha256_init(), sha256_update() and sha256_final(),
 * and places the resulting hash in @a out.
 * @param in Pointer to data to hash
 * @param inlen Length of @a in data, in bytes
 * @param out Pointer to location to place the message digest
*/
HOST_DEVICE_FN void sha256(const void *in, size_t inlen, void *out)
{
   SHA256_CTX ctx;

   sha256_init(&ctx);
   sha256_update(&ctx, in, inlen);
   sha256_final(&ctx, out);
}  /* end sha256() */

/* end include guard */
#endif
