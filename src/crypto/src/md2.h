/**
 * m2.h - MD2 hash function support header
 *   md2.h (8 April 2020)
 *
 * For more information, please refer to ./md2.c
 *
 * Date: 8 April 2020
 * Revised: 19 August 2021
 *
*/

#ifndef _MD2_H_
#define _MD2_H_  /* include guard */


#ifdef HASHTEST  /* MD2 testing header */
#include "hashtest.h"
#endif  /* end MD2 testing header */

#include <stddef.h>
#include <stdint.h>

#ifndef MD2LEN
#define MD2LEN  16
#endif

#define md2_transform_round(i)  \
   ctx->state[0] ^= s[( i )];           \
   ctx->state[1] ^= s[ctx->state[0]];   \
   ctx->state[2] ^= s[ctx->state[1]];   \
   ctx->state[3] ^= s[ctx->state[2]];   \
   ctx->state[4] ^= s[ctx->state[3]];   \
   ctx->state[5] ^= s[ctx->state[4]];   \
   ctx->state[6] ^= s[ctx->state[5]];   \
   ctx->state[7] ^= s[ctx->state[6]];   \
   ctx->state[8] ^= s[ctx->state[7]];   \
   ctx->state[9] ^= s[ctx->state[8]];   \
   ctx->state[10] ^= s[ctx->state[9]];  \
   ctx->state[11] ^= s[ctx->state[10]]; \
   ctx->state[12] ^= s[ctx->state[11]]; \
   ctx->state[13] ^= s[ctx->state[12]]; \
   ctx->state[14] ^= s[ctx->state[13]]; \
   ctx->state[15] ^= s[ctx->state[14]]; \
   ctx->state[16] ^= s[ctx->state[15]]; \
   ctx->state[17] ^= s[ctx->state[16]]; \
   ctx->state[18] ^= s[ctx->state[17]]; \
   ctx->state[19] ^= s[ctx->state[18]]; \
   ctx->state[20] ^= s[ctx->state[19]]; \
   ctx->state[21] ^= s[ctx->state[20]]; \
   ctx->state[22] ^= s[ctx->state[21]]; \
   ctx->state[23] ^= s[ctx->state[22]]; \
   ctx->state[24] ^= s[ctx->state[23]]; \
   ctx->state[25] ^= s[ctx->state[24]]; \
   ctx->state[26] ^= s[ctx->state[25]]; \
   ctx->state[27] ^= s[ctx->state[26]]; \
   ctx->state[28] ^= s[ctx->state[27]]; \
   ctx->state[29] ^= s[ctx->state[28]]; \
   ctx->state[30] ^= s[ctx->state[29]]; \
   ctx->state[31] ^= s[ctx->state[30]]; \
   ctx->state[32] ^= s[ctx->state[31]]; \
   ctx->state[33] ^= s[ctx->state[32]]; \
   ctx->state[34] ^= s[ctx->state[33]]; \
   ctx->state[35] ^= s[ctx->state[34]]; \
   ctx->state[36] ^= s[ctx->state[35]]; \
   ctx->state[37] ^= s[ctx->state[36]]; \
   ctx->state[38] ^= s[ctx->state[37]]; \
   ctx->state[39] ^= s[ctx->state[38]]; \
   ctx->state[40] ^= s[ctx->state[39]]; \
   ctx->state[41] ^= s[ctx->state[40]]; \
   ctx->state[42] ^= s[ctx->state[41]]; \
   ctx->state[43] ^= s[ctx->state[42]]; \
   ctx->state[44] ^= s[ctx->state[43]]; \
   ctx->state[45] ^= s[ctx->state[44]]; \
   ctx->state[46] ^= s[ctx->state[45]]; \
   ctx->state[47] ^= s[ctx->state[46]];

#ifdef __cplusplus
extern "C" {
#endif

/* MD2 context */
typedef struct {
   uint8_t data[16];
   uint8_t state[48];
   uint8_t checksum[16];
   uint32_t len;
} MD2_CTX;

/* MD2 transformation */
void md2_transform(MD2_CTX *ctx, uint8_t data[]);

/* Initialize the hashing context `ctx` */
void md2_init(MD2_CTX *ctx);

/* Add `inlen` bytes from `in` into the hash */
void md2_update(MD2_CTX *ctx, const void *in, size_t inlen);

/* Generate the message digest and place in `out` */
void md2_final(MD2_CTX *ctx, void *out);

/* Convenient all-in-one MD2 computation */
void md2(const void *in, size_t inlen, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _MD2_H_ */
