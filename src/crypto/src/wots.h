/**
 * wots.h - WOTS+ Public address, Signature, and Verification header
 *
 * Copyright (c) 2018-2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 25 May 2018
 * Revised: 26 October 2021
 *
*/

#ifndef _CRYPTO_WOTS_H_
#define _CRYPTO_WOTS_H_


#include "extint.h"  /* for word types */

/* Final wots+ output size */
#define WOTSSIGBYTES (WOTSLEN * PARAMSN)

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for wots.c */
void wots_pkgen(word8 *pk, const word8 *seed, const word8 *pub_seed,
                word32 addr[8]);
void wots_sign(word8 *sig, const word8 *msg, const word8 *seed,
               const word8 *pub_seed, word32 addr[8]);
void wots_pk_from_sig(word8 *pk, const word8 *sig, const word8 *msg,
                      const word8 *pub_seed, word32 addr[8]);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRYPTO_WOTS_H_ */
