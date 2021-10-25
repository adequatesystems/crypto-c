/**
 * peach.h - Peach Proof-of-Work algorithm header
 *
 * Copyright (c) 2019-2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 5 June 2019
 * Revised: 27 August 2021
 *
*/

#ifndef _POW_PEACH_H_
#define _POW_PEACH_H_  /* include guard */


#include <stdint.h>

#include "trigg.h"
#include "md2.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha3.h"
#include "blake2b.h"

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

#ifndef HASHLEN32
#define HASHLEN32  8  /* 32-bit variation to HASHLEN */
#endif


#ifdef __cplusplus
extern "C" {
#endif

/* Peach algorithm context */
typedef struct {
   SHA256_CTX ictx;                 /* partially completed SHA256 context */
   uint32_t dtile[PEACHTILELEN32];  /* backup tile data */
   uint8_t phash[HASHLEN];          /* previous block hash */
   uint8_t diff;                    /* the block diff */
} PEACH_POW;

/* Check proof of work. The haiku must be syntactically correct
 * and have the right vibe. Also, entropy MUST match difficulty.
 * If non-NULL, place final hash in `out` on success.
 * Return VEOK on success, else VERROR. */
#define peach_check(btp)  peach_checkhash(btp, NULL)
int peach_checkhash(BTRAILER *bt, void *out);

/* Initialize a PEACH context for solving, using a Block Trailer. */
void peach_init(PEACH_POW *P, BTRAILER *bt);

/* Try solve for a tokenized haiku as nonce output for proof of work.
 * Combine haiku protocols implemented in the Trigg Algorithm with the
 * memory intensive protocols of the Peach algorithm to generate haiku
 * output as proof of work. Place nonce into `out` on success.
 * Return VEOK on success, else VERROR. */
int peach_solve(PEACH_POW *P, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _POW_PEACH_H_ */
