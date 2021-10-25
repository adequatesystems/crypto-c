/* xo4.c - Crypto for shylock.c
 *
 * Copyright (c) 2018-2021 by Adequate Systems, LLC.  All Rights Reserved.
 * See LICENSE.PDF   **** NO WARRANTY ****
 *
 * Date: 17 February 2018
 * Revised: 20 September 2021
 *
 * --------  XO4 Cipher package  --------
 * Courtesy Patrick Cargill -- EYES ONLY!
 *
*/

#ifndef _ENCRYPT_XO4_C_
#define _ENCRYPT_XO4_C_


#include "sha256.h"
#include "xo4.h"

/* Initialise Cipher XO4
 * Key is a random seed of length len <= 64 bytes.
 */
void xo4_init(XO4_CTX *ctx, uint8_t *key, int len)
{
   int i, j, len2;

   for(i = 0, j = 0, len2 = len; i < 64; i++) {
      ctx->s[i] = key[j++];
      if(--len2 == 0) { j = 0; len2 = len; }
   }
   ctx->j = 0;
}

/* Return a random number between 0 and 255 */
uint8_t xo4_rand(XO4_CTX *ctx)
{
   int n;
   uint8_t b;

   if(ctx->j == 0) {
      /* increment big number in ctx->s[] */
      for(n = 0; n < 64; n++) {
         if(++(ctx->s[n]) != 0) break;
      }       
      sha256(ctx->s, 64, ctx->rnd);
   }
   b = ctx->rnd[ctx->j++];
   if(ctx->j >= 32) ctx->j = 0;
   return b;
}

void xo4_crypt(XO4_CTX *ctx, void *input, void *output, int len)
{
   uint8_t *in, *out;

   in = input;
   out = output;

   for(  ; len; len--)
      *out++ = *in++ ^ xo4_rand(ctx);
}


#endif  /* _ENCRYPT_XO4_C_ */
