/**
 * @private
 * @headerfile ripemd160.h <ripemd160.h>
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

/* include guard */
#ifndef CRYPTO_RIPEMD160_C
#define CRYPTO_RIPEMD160_C


#include "ripemd160.h"
#include <string.h>

#define BLOCK_LENGTH 64

static const uint32_t KL[] = {
   0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e
};
static const uint32_t KR[] = {
   0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000
};

static const uint32_t RL[] = {
   0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
   15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14,
   11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13,
   11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15,
   14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8,
   11, 6, 15, 13
};

static const uint32_t RR[] = {
   5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
   6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
   15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
   8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
   12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9,
   11
};

static const uint32_t SL[] = {
   11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7,
   9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11,
   7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13,
   6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9,
   14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12,
   5, 12, 13, 14, 11, 8, 5, 6
};

static const uint32_t SR[] = {
   8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14,
   12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6,
   15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5,
   14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6,
   9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6,
   8, 13, 6, 5, 15, 13, 11, 11
};

static uint32_t ff(int round, uint32_t x, uint32_t y, uint32_t z)
{
   switch (round) {
      case 1: return xor3(x, y, z);
      case 2: return xandx(x, y, z);
      case 3: return xoror(x, ~y, z);
      case 4: return xandx(z, x, y);
      case 5: return xoror(~z, y, x);
      default: return 0;
   }
}

/**
 * @private
 * RIPEMD160 compression rounds.
 * @param state Pointer to RIPEMD160 state
 * @param block Pointer to input to be compressed
*/
static void ripemd160_compress(uint32_t *state, const uint8_t *block)
{
   uint32_t a, aa, b, bb, c, cc, d, dd, e, ee, t, x[16];

   /* RIPEMD uses little endian byte ordering */
   for (int i = 0; i < 16; i++) {
      x[i] = get32le(block + (4 * i));
   }

   /* initialize state */
   a = aa = state[0];
   b = bb = state[1];
   c = cc = state[2];
   d = dd = state[3];
   e = ee = state[4];

   /* iterate through rounds */
   for (int jj, j = 0; j < 80; j++) {
      jj = j / 16;

      /* left */
      t = rol32(aa + ff(5 - jj, bb, cc, dd) + x[RR[j]] + KR[jj], SR[j]) + ee;
      aa = ee; ee = dd; dd = rol32(cc, 10); cc = bb; bb = t;

      /* right */
      t = rol32(a + ff(jj + 1, b, c, d) + x[RL[j]] + KL[jj], SL[j]) + e;
      a = e; e = d; d = rol32(c, 10); c = b; b = t;
   }

   /* final mixing round */
   t = state[1] + c + dd;
   state[1] = state[2] + d + ee;
   state[2] = state[3] + e + aa;
   state[3] = state[4] + a + bb;
   state[4] = state[0] + b + cc;
   state[0] = t;
}  /* end ripemd160_compress() */

/**
 * Initialize a RIPEMD160 context.
 * @param ctx Pointer to RIPEMD160 context
*/
void ripemd160_init(RIPEMD160_CTX *ctx)
{
   ctx->state[0] = 0x67452301;
   ctx->state[1] = 0xefcdab89;
   ctx->state[2] = 0x98badcfe;
   ctx->state[3] = 0x10325476;
   ctx->state[4] = 0xc3d2e1f0;
   ctx->total = 0;
   memset(ctx->buffer, 0, sizeof(ctx->buffer));
}  /* end ripemd160_init() */

/**
 * Add @a inlen bytes from @a in to a RIPEMD160 context for hashing.
 * @param ctx Pointer to RIPEMD160 context
 * @param in Pointer to data to hash
 * @param inlen Length of @a in data, in bytes
*/
void ripemd160_update(RIPEMD160_CTX *ctx, const void *in, size_t inlen)
{
   size_t idx, fill;

   idx = ctx->total & (BLOCK_LENGTH - 1);
   fill = BLOCK_LENGTH - idx;
   ctx->total += inlen;

   if (inlen >= fill) {
      memcpy(ctx->buffer + idx, in, fill);
      ripemd160_compress(ctx->state, ctx->buffer);
      in = ((uint8_t *) in) + fill;
      inlen -= fill;
      while (inlen >= BLOCK_LENGTH) {
         ripemd160_compress(ctx->state, in);
         in = ((uint8_t *) in) + BLOCK_LENGTH;
         inlen -= BLOCK_LENGTH;
      }
      idx = 0;
   }

   if (inlen > 0) {
      memcpy(ctx->buffer + idx, in, inlen);
   }
}  /* end ripemd160_update() */

/**
 * Finalize a RIPEMD160 message digest.
 * Generate the RIPEMD160 message digest and place in @a out.
 * @param ctx Pointer to RIPEMD160 context
 * @param out Pointer to location to place the message digest
*/
void ripemd160_final(RIPEMD160_CTX *ctx, void *out)
{
   uint8_t final[BLOCK_LENGTH] = { 0x80, 0 };

   size_t idx, len;

   idx = ctx->total & (BLOCK_LENGTH - 1);
   len = (idx < 56) ? (56 - idx) : (120 - idx);

   /* place total bit length in last 8 bytes */
   put32le(final + len, ctx->total << 3);
   put32le(final + len + 4, ctx->total >> 29);
   /* perform final update (and compress) */
   ripemd160_update(ctx, final, len + 8);

   /* RIPEMD uses little endian byte ordering */
   put32le(out, ctx->state[0]);
   put32le(((uint8_t *) out) + 4, ctx->state[1]);
   put32le(((uint8_t *) out) + 8, ctx->state[2]);
   put32le(((uint8_t *) out) + 12, ctx->state[3]);
   put32le(((uint8_t *) out) + 16, ctx->state[4]);
}  /* end ripemd160_final() */

/**
 * Convenient all-in-one RIPEMD160 computation.
 * Performs RIPEMD160_init(), RIPEMD160_update() and RIPEMD160_final(),
 * and places the resulting hash in @a out.
 * @param in Pointer to data to hash
 * @param inlen Length of @a in data, in bytes
 * @param out Pointer to location to place the message digest
*/
void ripemd160(const void *in, size_t inlen, uint8_t *out)
{
   RIPEMD160_CTX ctx;

   ripemd160_init(&ctx);
   ripemd160_update(&ctx, in, inlen);
   ripemd160_final(&ctx, out);
}

/* end include guard */
#endif
