/**
 * m2.h - MD2 hash function support header
 *
 * For more information, please refer to ./md2.c
 *
 * Date: 8 April 2020
 * Revised: 26 October 2021
 *
*/

#ifndef _CRYPTO_MD2_H_
#define _CRYPTO_MD2_H_  /* include guard */


#include <stddef.h>  /* for size_t */
#include "extint.h"  /* for word types */

/* MD5 specific parameters */
#define MD2LEN 16

/* MD2 context */
typedef struct {
   word8 data[16];
   word8 state[48];
   word8 checksum[16];
   word32 len;
} MD2_CTX;

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for md2.c */
void md2_init(MD2_CTX *ctx);
void md2_update(MD2_CTX *ctx, const void *in, size_t inlen);
void md2_final(MD2_CTX *ctx, void *out);
void md2(const void *in, size_t inlen, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRYPTO_MD2_H_ */
