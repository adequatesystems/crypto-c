/**
 * trigg.h - Trigg's Proof-of-Work algorithm header
 *
 * Copyright (c) 2020-2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 5 May 2020
 * Revised: 27 August 2021
 *
*/

#ifndef _POW_TRIGG_H_
#define _POW_TRIGG_H_  /* include guard */

#include <stdint.h>
#include "sha256.h"

/* ============================================================= */
#ifdef ENABLE_THREADSAFE /* for multithreading safe capabilities */

#include "thread.h"

/* determine if system is capable of reading 32-bits in one operation */
#if (INTPTR_MAX < INT32_MAX)
/* The above preprocessor conditional determines if the system is capable of
 * reading 32-bits of data in a single operation. In such a case, obtaining
 * the random value within Trigg_seed at any given time cannot be guarenteed
 * consistant. As such, a mutex will be required for the read operation. */

/* Removeable function redefinitions for reads only (active) */
#define trigg_rand_unlock_rd32  mutex_unlock(&Trigg_rand_mutex)
#define trigg_rand_lock_rd32    mutex_lock(&Trigg_rand_mutex)

#else

#define trigg_rand_unlock_rd32()  /* do nothing */
#define trigg_rand_lock_rd32()    /* do nothing */

#endif 

/* Removeable function redefinitions (active) */
#define trigg_rand_unlock()     mutex_unlock(&Trigg_rand_mutex)
#define trigg_rand_lock()       mutex_lock(&Trigg_rand_mutex)

/* Restricted use Mutex guard for number generator */
static volatile Mutex Trigg_rand_mutex;

#else

#define trigg_rand_unlock_rd32()  /* do nothing */
#define trigg_rand_lock_rd32()    /* do nothing */
#define trigg_rand_unlock()       /* do nothing */
#define trigg_rand_lock()         /* do nothing */

#endif  /* end ... else ... ENABLE_THREADSAFE */
/* ========================================== */


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

#define TCHAINLEN     312
#define HAIKUCHARLEN  256
#define MAXDICT       256
#define MAXDICT_M1    255
#define MAXH          16
#define NFRAMES       10

#ifndef HASHLEN
#define HASHLEN  32
#endif

#ifndef VEOK
#define VEOK     0
#endif

#ifndef VERROR
#define VERROR   1
#endif


#ifdef __cplusplus
extern "C" {
#endif

#ifndef BTSIZE
#define BTSIZE  160
typedef struct {  /* The block trailer struct... */
   uint8_t phash[HASHLEN];  /* previous block hash (32) */
   uint8_t bnum[8];         /* this block number */
   uint8_t mfee[8];         /* minimum transaction fee */
   uint8_t tcount[4];       /* transaction count */
   uint8_t time0[4];        /* to compute next difficulty */
   uint8_t difficulty[4];   /* difficulty of block */
   uint8_t mroot[HASHLEN];  /* hash of all TXQENTRY's */
   uint8_t nonce[HASHLEN];  /* haiku */
   uint8_t stime[4];        /* unsigned solve time GMT seconds */
   uint8_t bhash[HASHLEN];  /* hash of all block less bhash[] */
} BTRAILER;
#endif  /* ... end block trailer struct */

/* Dictionary entry with semantic grammar features */
typedef struct {
  uint8_t tok[12];  /* word token */
  uint32_t fe;      /* semantic features */
} DICT;

/* Generate a tokenized haiku into `out` using the embedded prng. */
void *trigg_generate(void *out);

/* Expand a haiku to character format.
 * It must have the correct syntax and vibe. */
char *trigg_expand(void *nonce, void *haiku);

/* Evaluate the TRIGG chain by using a heuristic estimate of the
 * final solution cost (Nilsson, 1971). Evaluate the relative
 * distance within the TRIGG chain to validate proof of work.
 * Return VEOK if solved, else VERROR. */
int trigg_eval(void *hash, uint8_t diff);

/* Check haiku syntax against semantic grammar.
 * It must have the correct syntax, semantics, and vibe.
 * Return VEOK on correct syntax, else VERROR. */
int trigg_syntax(void *nonce);

/* Check proof of work. The haiku must be syntactically correct
 * and have the right vibe. Also, entropy MUST match difficulty.
 * If non-NULL, place final hash in `out` on success.
 * Return VEOK on success, else VERROR. */
#define trigg_check(btp)  trigg_checkhash(btp, NULL)
int trigg_checkhash(BTRAILER *bt, void *out);

/* Trigg algorithm context */
typedef struct {
   /* TRIGG chain... */
   uint8_t mroot[HASHLEN];       /* merkle root from block trailer */
   uint8_t haiku[HAIKUCHARLEN];  /* expanded haiku */
   uint8_t nonce2[16];           /* tokenized haiku (secondary): */
   uint8_t bnum[8];              /* block number */
   /* ... end TRIGG chain */
   uint8_t nonce1[16];           /* tokenized haiku (primary): */
   uint8_t diff;                 /* the block diff */
} TRIGG_POW;

/* Prepare a TRIGG context for solving. */
void trigg_init(TRIGG_POW *T, BTRAILER *bt);

/* Generate a tokenized haiku as nonce output for proof of work.
 * Create the haiku inside the TRIGG chain using a semantic grammar
 * (Burton, 1976). The output must pass syntax checks, the entropy
 * check, and have the right vibe. Entropy is always preserved at
 * high difficulty levels. Place nonce into `out` on success.
 * Return VEOK on success, else VERROR. */
int trigg_solve(TRIGG_POW *T, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _POW_TRIGG_H_ */
