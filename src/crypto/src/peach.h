/**
 * peach.h - Peach Proof-of-Work algorithm header
 *
 * Copyright (c) 2019-2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 5 June 2019
 * Revised: 26 October 2021
 *
*/

#ifndef _CRYPTO_PEACH_H_
#define _CRYPTO_PEACH_H_  /* include guard */


#include <string.h>  /* for mem handling */
#include "extint.h"  /* for word types */
#include "trigg.h"   /* for evaluation and haiku generation */

/* hashing functions used by Peach's nighthash */
#include "blake2b.h"
#include "md2.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha3.h"

/* Peach specific parameters */
#define PEACHGENLEN      36          /* (HASHLEN + 4) */
#define PEACHJUMPLEN     1060        /* (HASHLEN + 4 + PEACH_TILE) */
#define PEACHMAPLEN      1073741824  /* 1 GiByte, (PEACH_CACHE * PEACH_TILE) */
#define PEACHMAPLEN64    134217728   /* 64-bit variation to PEACH_MAP */
#define PEACHCACHELEN    1048576     /* 1 MiByte, (PEACH_TILE * PEACH_TILE) */
#define PEACHCACHELEN_M1 1048575     /* PEACHCACHELEN mask */
#define PEACHCACHELEN64  131072      /* 64-bit variation to PEACH_CACHE */
#define PEACHTILELEN     1024        /* 1 KiByte, (PEACH_ROW * HASHLEN) */
#define PEACHTILELEN_M1  1023        /* PEACHTILELEN mask */
#define PEACHTILELEN32   256         /* 32-bit variation to PEACH_TILE */
#define PEACHTILELEN64   128         /* 64-bit variation to PEACH_TILE */
#define PEACHROWLEN      32          /* 32 Byte, HASHLEN */
#define PEACHROUNDS      8

/* Peach algorithm context */
typedef struct {
   SHA256_CTX ictx;                 /* partially completed SHA256 context */
   word32 dtile[PEACHTILELEN32];  /* backup tile data */
   word8 phash[SHA256LEN];        /* previous block hash */
   word8 diff;                    /* the block diff */
} PEACH_POW;  /* ... end Peach POW struct */

/* Check Peach's Proof of Work without passing the final hash */
#define peach_check(btp)  peach_checkhash(btp, NULL)

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes forpeach.c */
int peach_checkhash(BTRAILER *bt, void *out);
void peach_init(PEACH_POW *P, BTRAILER *bt);
int peach_solve(PEACH_POW *P, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRYPTO_PEACH_H_ */
