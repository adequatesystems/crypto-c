/* xo4.c - Crypto for shylock.c
 *
 * Copyright (c) 2021 by Adequate Systems, LLC.  All Rights Reserved.
 * See LICENSE.PDF   **** NO WARRANTY ****
 *
 * Date: 20 September 2021
 *
 * --------  XO4 Cipher package  --------
 * Courtesy Patrick Cargill -- EYES ONLY!
 *
*/

#ifndef _ENCRYPT_XO4_H_
#define _ENCRYPT_XO4_H_


#include  <stdint.h>

typedef struct {
   uint8_t s[64];
   uint8_t rnd[32];
   int j;
} XO4_CTX;

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise Cipher XO4
 * Key is a random seed of length len <= 64 bytes.
 */
void xo4_init(XO4_CTX *ctx, uint8_t *key, int len);

/* Return a random number between 0 and 255 */
uint8_t xo4_rand(XO4_CTX *ctx);

void xo4_crypt(XO4_CTX *ctx, void *input, void *output, int len);

#ifdef __cplusplus
}
#endif


#endif  /* _ENCRYPT_XO4_H_ */
