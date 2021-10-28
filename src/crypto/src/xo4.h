/**
 * xo4.h - Crypto support header for shylock.c
 *
 * Copyright (c) 2021 by Adequate Systems, LLC.  All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 20 September 2021
 * Revised: 26 October 2021
 *
 * --------  XO4 Cipher package  --------
 * Courtesy Patrick Cargill -- EYES ONLY!
 *
*/

#ifndef _CRYPTO_XO4_H_
#define _CRYPTO_XO4_H_


#include <stddef.h>  /* for size_t */
#include "extint.h"  /* for word types */

typedef struct {
   word8 s[64];
   word8 rnd[32];
   int j;
} XO4_CTX;

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for xo4.c */
void xo4_init(XO4_CTX *ctx, void *key, size_t len);
void xo4_crypt(XO4_CTX *ctx, void *input, void *output, size_t len);

#ifdef __cplusplus
}
#endif


#endif  /* _CRYPTO_XO4_H_ */
