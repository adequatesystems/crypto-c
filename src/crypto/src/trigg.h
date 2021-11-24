/**
 * trigg.h - Trigg's Proof-of-Work algorithm header
 *
 * Copyright (c) 2020-2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 5 May 2020
 * Revised: 26 October 2021
 *
*/

#ifndef _CRYPTO_TRIGG_H_
#define _CRYPTO_TRIGG_H_  /* include guard */


#include "extint.h"  /* for word types */
#include "extlib.h"  /* for rand16() */
#include "sha256.h"

/* The features for the semantic grammar are
 * adapted from systemic grammar (Winograd, 1972). */
#define F_ING         1
#define F_INF         2
#define F_MOTION      4
#define F_VB          ( F_INT | F_INT | F_MOTION )

#define F_NS          8
#define F_NPL         16
#define F_N           ( F_NS | F_NPL )
#define F_MASS        32
#define F_AMB         64
#define F_TIMED       128
#define F_TIMEY       256
#define F_TIME        ( F_TIMED | F_TIMEY )
#define F_AT          512
#define F_ON          1024
#define F_IN          2048
#define F_LOC         ( F_AT | F_ON | F_IN )
#define F_NOUN        ( F_NS | F_NPL | F_MASS | F_TIME | F_LOC )

#define F_PREP        0x1000
#define F_ADJ         0x2000
#define F_OP          0x4000
#define F_DETS        0x8000
#define F_DETPL       0x10000
#define F_XLIT        0x20000

#define S_NL          ( F_XLIT + 1 )
#define S_CO          ( F_XLIT + 2 )
#define S_MD          ( F_XLIT + 3 )
#define S_LIKE        ( F_XLIT + 4 )
#define S_A           ( F_XLIT + 5 )
#define S_THE         ( F_XLIT + 6 )
#define S_OF          ( F_XLIT + 7 )
#define S_NO          ( F_XLIT + 8 )
#define S_S           ( F_XLIT + 9 )
#define S_AFTER       ( F_XLIT + 10 )
#define S_BEFORE      ( F_XLIT + 11 )

#define S_AT          ( F_XLIT + 12 )
#define S_IN          ( F_XLIT + 13 )
#define S_ON          ( F_XLIT + 14 )
#define S_UNDER       ( F_XLIT + 15 )
#define S_ABOVE       ( F_XLIT + 16 )
#define S_BELOW       ( F_XLIT + 17 )

/* Trigg specific parameters */
#define TCHAINLEN     312
#define HAIKUCHARLEN  256
#define MAXDICT       256
#define MAXDICT_M1    255
#define MAXH          16
#define NFRAMES       10

/* Dictionary entry with semantic grammar features */
typedef struct {
  word8 tok[12];  /* word token */
  word32 fe;      /* semantic features */
} DICT;

/* Trigg algorithm context */
typedef struct {
   /* TRIGG chain... */
   word8 mroot[SHA256LEN];     /* merkle root from block trailer */
   word8 haiku[HAIKUCHARLEN];  /* expanded haiku */
   word8 nonce2[16];           /* tokenized haiku (secondary): */
   word8 bnum[8];              /* block number */
   /* ... end TRIGG chain */
   word8 nonce1[16];           /* tokenized haiku (primary): */
   word8 diff;                 /* the block diff */
} TRIGG_POW;  /* ... end Trigg POW struct */

/* Mochimo specific configuration */
#ifndef VEOK
#define VEOK     0
#endif
#ifndef VERROR
#define VERROR   1
#endif
#ifndef BTSIZE
#define BTSIZE  160
typedef struct {  /* The block trailer struct... */
   word8 phash[SHA256LEN];  /* previous block hash (32) */
   word8 bnum[8];           /* this block number */
   word8 mfee[8];           /* minimum transaction fee */
   word8 tcount[4];         /* transaction count */
   word8 time0[4];          /* to compute next difficulty */
   word8 difficulty[4];     /* difficulty of block */
   word8 mroot[SHA256LEN];  /* hash of all TXQENTRY's */
   word8 nonce[SHA256LEN];  /* haiku */
   word8 stime[4];          /* unsigned solve time GMT seconds */
   word8 bhash[SHA256LEN];  /* hash of all block less bhash[] */
} BTRAILER;  /* ... end block trailer struct */
#endif

/* Check Trigg's Proof of Work without passing the final hash */
#define trigg_check(btp)  trigg_checkhash(btp, NULL)

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for trigg.c. */
void *trigg_generate(void *out);
char *trigg_expand(void *nonce, void *haiku);
int trigg_eval(void *hash, word8 diff);
int trigg_syntax(void *nonce);
int trigg_checkhash(BTRAILER *bt, void *out);
void trigg_init(TRIGG_POW *T, BTRAILER *bt);
int trigg_solve(TRIGG_POW *T, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRYPTO_TRIGG_H_ */
