/**
 * xo4.c - Crypto support for shylock.c
 *
 * Copyright (c) 2018-2021 by Adequate Systems, LLC.  All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 17 February 2018
 * Revised: 26 October 2021
 *
 * --------  XO4 Cipher package  --------
 * Courtesy Patrick Cargill -- EYES ONLY!
 *
*/

#ifndef _CRYPTO_XO4_C_
#define _CRYPTO_XO4_C_


#include "xo4.h"
#include "sha256.h"

/* Initialise Cipher XO4
 * Key is a random seed of length len <= 64 bytes. */
void xo4_init(XO4_CTX *ctx, void *key, size_t len)
{
   int i, j, len2;

   for(i = 0, j = 0, len2 = len; i < 64; i++) {
      ctx->s[i] = ((word8 *) key)[j++];
      if(--len2 == 0) { j = 0; len2 = len; }
   }
   ctx->j = 0;
}  /* end xo4_init() */

/* Return a random number between 0 and 255 */
static word8 xo4_rand(XO4_CTX *ctx)
{
   int n;
   word8 b;

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
}  /* end xo4_rand() */

void xo4_crypt(XO4_CTX *ctx, void *input, void *output, size_t len)
{
   word8 *in, *out;

   in = input;
   out = output;

   for(  ; len; len--) {
      *out++ = *in++ ^ xo4_rand(ctx);
   }
}  /* end xo4_crypt() */


#endif  /* _CRYPTO_XO4_C_ */
