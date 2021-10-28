/**
 * peach.c - Peach Proof-of-Work algorithm (FPGA-"tough")
 *
 * Copyright (c) 2019-2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 5 June 2019
 * Revised: 26 October 2021
 *
 * The Peach algorithm appears to be designed with the intention of
 * permitting a "mining advantage" to modern GPUs with >1GiB memory
 * capacity where it can cache and re-obtain a large amount of data
 * faster than it would take to re-compute it.
 *
 * The cache is made of 1048576 x 1KibiByte chunks (a.k.a tiles) of
 * data, generated deterministically from the previous blocks hash,
 * making it unique per block solve. The generation process, dubbed
 * Nighthash, generates chunks using deterministic single precision
 * floating point operations, a selection of eight different memory
 * transformations, and finally a selection of eight different hash
 * algorithms. The final digest is then placed within the first row
 * of a tile. Subsequent rows are filled in the same manner, except
 * they use the previous row as input until the chunk is completed.
 *
 * Peach also utilizes the nonce restrictions designed for use with
 * Trigg's algorithm, to retain the pleasantries of using haikus.
 *
 *    a raindrop
 *    on sunrise air--
 *    drowned
 *
 * NOTES:
 * - Presently, due to the underlying reliance on the C99 standard for
 *   floating point NaN detection and strict IEEE 754 compliance, as
 *   well as some underlying hash functions (Blake2b and SHA3), this
 *   implementation CANNOT RUN on systems that rely on C89 compliance.
 *   Ergo, 64-bit optimisations WILL NOT have 32-bit alternatives.
 * - Where resources are plenty, define -DENABLE_STATIC_PEACH_MAP.
 *   This enables a 1GiB matrix for increased solving performance.
 *
*/

#ifndef _CRYPTO_PEACH_C_
#define _CRYPTO_PEACH_C_  /* include guard */


#include <math.h>  /* for isnan() */
#include "peach.h"

/* Perform deterministic (single precision) floating point operations
 * on a chunk of data (in 4 byte chunks). Operations are only
 * guarenteed "deterministic" for IEEE-754 compliant hardware.
 * Returns an operation identifier as a 32-bit unsigned integer. */
static inline word32 peach_dflops
(void *data, size_t len, word32 index, int txf)
{
   word32 op;
   int32 operand;
   float *flp, temp, flv;
   word8 *bp, shift;
   unsigned i;

   /* process entire length of input data; limit to 4 byte multiples */
   len = len - (len & 3);
   for (i = op = 0; i < len; i += 4, bp += 4) {
      bp = &((word8 *) data)[i];
      if (txf) {
         /* input data is modified directly */
         flp = (float *) bp;
      } else {
         /* temp variable is modified, input data is unchanged */
         temp = *((float *) bp);
         flp = &temp;
      }
      /* first byte allocated to determine shift amount */
      shift = ((*bp & 7) + 1) << 1;
      /* remaining bytes are selected for 3 different operations based on
       * the first bytes resulting shift on precomputed contants to...
       * ... 1) determine the floating point operation type */
      op += bp[((WORD32_C(0x26C34) >> shift) & 3)];
      /* ... 2) determine the value of the operand */
      operand = bp[((WORD32_C(0x14198) >> shift) & 3)];
      /* ... 3) determine the upper most bit of the operand
       *        NOTE: must be performed AFTER the allocation of the operand */
      if (bp[((WORD32_C(0x3D6EC) >> shift) & 3)] & 1) {
         operand ^= WORD32_C(0x80000000);
      }
      /* interpret operand as SIGNED integer and cast to float */
      flv = (float) operand;
      /* Replace pre-operation NaN with index */
      if (isnan(*flp)) *flp = (float) index;
      /* Perform predetermined floating point operation */
      switch (op & 3) {
         case 3:  *flp /= flv;  break;
         case 2:  *flp *= flv;  break;
         case 1:  *flp -= flv;  break;
         default: *flp += flv;  break;
      }
      /* Replace post-operation NaN with index */
      if (isnan(*flp)) *flp = (float) index;
      /* Add result of the operation to `op` as an array of bytes */
      bp = (word8 *) flp;
      op += bp[0];
      op += bp[1];
      op += bp[2];
      op += bp[3];
   }  /* end for(i = 0; ... */

   return op;
}  /* end peach_dflops() */

/* Perform deterministic memory transformations on a chunk of data.
 * Returns a modified operation identifier as a 32-bit unsigned integer. */
static inline word32 peach_dmemtx(void *data, size_t len, word32 op)
{
   size_t len16, len32, len64, y;
   word64 *qp;
   word32 *dp;
   word8 *bp, temp;
   unsigned i, z;

   /* prepare memory pointers and lengths */
   bp = (word8 *) data;
   dp = (word32 *) data;
   qp = (word64 *) data;
   len16 = len >> 1;
   len32 = len >> 2;
   len64 = len >> 3;
   /* perform memory transformations multiple times */
   for (i = 0; i < PEACHROUNDS; i++) {
      /* determine operation to use for this iteration */
      op += bp[i & 31];
      /* select "random" transformation based on value of `op` */
      switch (op & 7) {
         case 0:  /* flip the first and last bit in every byte */
            for (z = 0; z < len64; z++) qp[z] ^= WORD64_C(0x8181818181818181);
            for (z <<= 1; z < len32; z++) dp[z] ^= WORD32_C(0x81818181);
            break;
         case 1:  /* Swap bytes */
            for (y = len16, z = 0; z < len16; y++, z++) {
               temp = bp[z]; bp[z] = bp[y]; bp[y] = temp;
            }
            break;
         case 2:  /* 1's complement, all bytes */
            for (z = 0; z < len64; z++) qp[z] = ~qp[z];
            for (z <<= 1; z < len32; z++) dp[z] = ~dp[z];
            break;
         case 3:  /* Alternate +1 and -1 on all bytes */
            for (z = 0; z < len; z++) bp[z] += (z & 1) ? -1 : 1;
            break;
         case 4:  /* Alternate -i and +i on all bytes */
            for (z = 0; z < len; z++) bp[z] += (word8) ((z & 1) ? i : -i);
            break;
         case 5:  /* Replace every occurrence of 104 with 72 */ 
            for (z = 0; z < len; z++) if(bp[z] == 104) bp[z] = 72;
            break;
         case 6:  /* If byte a is > byte b, swap them. */
            for (y = len16, z = 0; z < len16; y++, z++) {
               if(bp[z] > bp[y]) {
                  temp = bp[z]; bp[z] = bp[y]; bp[y] = temp;
               }
            }
            break;
         case 7:  /* XOR all bytes */
            for (y = 0, z = 1; z < len; y++, z++) bp[z] ^= bp[y];
            break;
      } /* end switch(op & 7)... */
   } /* end for(i = 0; ... */

   return op;
}  /* end peach_dmemtx() */

/* Perform Nighthash on in[inlen] and place result in out[].
 * Utilizes deterministic float operations and memory transformations. */
static void peach_nighthash
(void *in, size_t inlen, word32 index, int hashindex, int txf, void *out)
{
   /* Standard contributing guidelines are ignored here to reduce
    * the amount of resources wasted in declaring contexts for all
    * eight (8) available algorithms and only using one (1) of them.
    * This should remain until such time as each algorithm can be
    * streamlined into separate optimized algorithms.

   BLAKE2B_CTX blake2b_ctx;
   SHA1_CTX sha1_ctx;
   SHA256_CTX sha256_ctx;
   SHA3_CTX sha3_ctx;
   KECCAK_CTX keccak_ctx;
   MD2_CTX md2_ctx;
   MD5_CTX md5_ctx; */

   /* Perform flops to determine initial algo type.
    * The `txf` option enables the transformation of input data,
    * as well as the additional memory transformation process. */
   word32 algo_type = peach_dflops(in, inlen, index, txf);
   if(txf) algo_type = peach_dmemtx(in, inlen, algo_type);

   /* reduce algorithm selection to 1 of 8 choices */
   algo_type &= 7;
   switch (algo_type) {
      case 0:   /* Blake2b w/ 32 byte key */
      case 1: { /* Blake2b w/ 64 byte key */
         BLAKE2B_CTX blake2b_ctx;
         word64 key[8];
         /* declare and determine key length */
         int keylen = algo_type ? 64 : 32;
         /* set the value of key as repeating algo_type */
         memset(key, algo_type, keylen);
         /* initialize context and perform blake2b w/ keylen size key */
         blake2b_init(&blake2b_ctx, key, keylen, BLAKE2BLEN256);
         blake2b_update(&blake2b_ctx, in, inlen);
         if (hashindex) blake2b_update(&blake2b_ctx, &index, 4);
         blake2b_final(&blake2b_ctx, out);
         return;
      }  /* end case 0: ... case 1: ... */
      case 2: { /* SHA1 */
         SHA1_CTX sha1_ctx;
         /* initialize context and perform algorithm */
         sha1_init(&sha1_ctx);
         sha1_update(&sha1_ctx, in, inlen);
         if (hashindex) sha1_update(&sha1_ctx, &index, 4);
         sha1_final(&sha1_ctx, out);
         /* SHA1 hash is only 20 bytes long, zero fill remaining... */
         ((word32 *) out)[5] = 0;
         ((word64 *) out)[3] = 0;
         return;
      }  /* end case 2: ... */
      case 3: { /* SHA256 */
         SHA256_CTX sha256_ctx;
         /* initialize context and perform algorithm */
         sha256_init(&sha256_ctx);
         sha256_update(&sha256_ctx, in, inlen);
         if (hashindex) sha256_update(&sha256_ctx, &index, 4);
         sha256_final(&sha256_ctx, out);
         return;
      }  /* end case 3: ... */
      case 4:   /* SHA3 */
      case 5: { /* Keccak */
         SHA3_CTX sha3_ctx;
      /* KECCAK_CTX keccak_ctx;  // same as SHA3_CTX... */
         /* initialize context and perform algorithm */
         sha3_init(&sha3_ctx, SHA3LEN256);
         sha3_update(&sha3_ctx, in, inlen);
         if (hashindex) sha3_update(&sha3_ctx, &index, 4);
         if (algo_type == 4) sha3_final(&sha3_ctx, out);
         else keccak_final(&sha3_ctx, out);
         return;
      }  /* end case 4: ... case 5: ... */
      case 6: { /* MD2 */
         MD2_CTX md2_ctx;
         /* initialize context and perform algorithm */
         md2_init(&md2_ctx);
         md2_update(&md2_ctx, in, inlen);
         if (hashindex) md2_update(&md2_ctx, &index, 4);
         md2_final(&md2_ctx, out);
         /* MD2 hash is only 16 bytes long, zero fill remaining... */
         ((word64 *) out)[2] = 0;
         ((word64 *) out)[3] = 0;
         return;
      }  /* end case 6: ... */
      case 7: { /* MD5 */
         MD5_CTX md5_ctx;
         /* initialize context and perform algorithm */
         md5_init(&md5_ctx);
         md5_update(&md5_ctx, in, inlen);
         if (hashindex) md5_update(&md5_ctx, &index, 4);
         md5_final(&md5_ctx, out);
         /* MD5 hash is only 16 bytes long, zero fill remaining... */
         ((word64 *) out)[2] = 0;
         ((word64 *) out)[3] = 0;
         return;
      }  /* end case 7: ... */
   }  /* end switch(algo_type)... */
}  /* end peach_nighthash() */

/* Generate a tile of data. Use PeachCache if allowed.
 * Note: Builds initial Nighthash seed within out then overwrites it.
 * Returns a pointer to the beginning of the generated tile. */
static word32 *peach_generate(word32 index, void *phash, void *out)
{
   word32 *dtile = (word32 *) out;
   int i;

   /* initially use the tile itself to build a seed for Nighthash */
   memcpy(dtile, &index, 4);
   memcpy(dtile + 1, phash, SHA256LEN);
   /* perform initial nighthash */
   peach_nighthash(dtile, PEACHGENLEN, index, 0, 1, dtile);
   /* fill the rest of the tile with the preceding Nighthash result */
   for (i = 0; i < 248; i += 8) {
      peach_nighthash(&dtile[i], SHA256LEN, index, 1, 1, &dtile[i + 8]);
   }

   return dtile;
}  /* end peach_generate() */

/* Perform an index jump using the hash result of the Nighthash function.
 * Returns the next index as a 32-bit unsigned integer. */
static word32 peach_jump(word32 index, void *nonce, void *tilep)
{
   word32 dhash[SHA256LEN / 4];
   word8 seed[PEACHJUMPLEN];

   /* construct seed for use as Nighthash input for this index on the map */
   memcpy(seed, nonce, SHA256LEN);
   memcpy(seed + SHA256LEN, &index, 4);
   memcpy(seed + SHA256LEN + 4, tilep, PEACHTILELEN);
   /* perform nighthash on PEACHJUMPLEN bytes of seed */
   peach_nighthash(seed, PEACHJUMPLEN, index, 0, 0, dhash);
   /* add hash onto index as addition of 8x 32-bit unsigned integers */
   index = dhash[0] + dhash[1] + dhash[2] + dhash[3] +
           dhash[4] + dhash[5] + dhash[6] + dhash[7];

   return index & PEACHCACHELEN_M1;
}  /* end peach_jump() */

/* Check proof of work. The haiku must be syntactically correct
 * and have the right vibe. Also, entropy MUST match difficulty.
 * If non-NULL, place final hash in `out` on success.
 * Return VEOK on success, else VERROR. */
int peach_checkhash(BTRAILER *bt, void *out)
{
   SHA256_CTX ictx;
   word32 mario, *tilep, dtile[PEACHTILELEN32];
   word8 hash[SHA256LEN] = { 0 };
   int i;

   /* check syntax, semantics, and vibe... */
   if(trigg_syntax(bt->nonce) == VERROR) return VERROR;
   if(trigg_syntax(bt->nonce + 16) == VERROR) return VERROR;
   /* perform initial hash of block trailer (partial) */
   sha256_init(&ictx);
   sha256_update(&ictx, bt, 124);
   sha256_final(&ictx, hash);
   /* initialize mario's starting index on the map, bound to PEACHCACHELEN */
   for(mario = hash[0], i = 1; i < SHA256LEN; i++) mario *= hash[i];
   mario &= PEACHCACHELEN_M1;
   /* generate tile at index, then determine next jump, for PEACHROUNDS, ... */
   for(i = 0; i < PEACHROUNDS; i++) {
      tilep = peach_generate(mario, bt->phash, dtile);
      mario = peach_jump(mario, bt->nonce, tilep);
   } /* ... then generate final tile for hashing */
   tilep = peach_generate(mario, bt->phash, dtile);
   /* hash block trailer with final tile */
   sha256_init(&ictx);
   sha256_update(&ictx, hash, SHA256LEN);
   sha256_update(&ictx, tilep, PEACHTILELEN);
   sha256_final(&ictx, hash);
   /* where `out` pointer is supplied, copy final hash */
   if(out != NULL) memcpy(out, hash, SHA256LEN);
   /* return trigg's evaluation of the final hash */
   return trigg_eval(hash, bt->difficulty[0]);
}  /* end peach_checkhash() */

/* Define restricted use Peach semaphores */
#ifdef ENABLE_STATIC_PEACH_MAP
static word8 PeachMap[PEACHMAPLEN];      /* 1GiByte! */
static word8 PeachCache[PEACHCACHELEN];  /* 1MiByte! */
static word8 PeachCleared[SHA256LEN];    /* clearhash */
#endif

/* Initialize a PEACH context for solving, using a Block Trailer. */
void peach_init(PEACH_POW *P, BTRAILER *bt)
{
#ifdef ENABLE_STATIC_PEACH_MAP
   if (memcmp(PeachCleared, bt->phash, SHA256LEN)) {
      /* store last hash the cache was cleared for */
      memcpy(PeachCleared, bt->phash, SHA256LEN);
      /* clear Map and Cache data */
      word64 *zp = (word64 *) PeachCache;
      for (int i = 0; i < PEACHCACHELEN64; zp[i++] = 0);
   }
#endif

   /* pre-compute partial SHA256 of block trailer */
   sha256_init(&(P->ictx));
   sha256_update(&(P->ictx), bt, 92);
   /* copy difficulty and previous hash from block trailer */
   memcpy(P->phash, bt->phash, SHA256LEN);
   /* place required difficulty in diff */
   P->diff = bt->difficulty[0];
}  /* end peach_init() */

static inline word32 *peach_generate2solve
(word32 index, void *phash, void *out)
{
#ifdef ENABLE_STATIC_PEACH_MAP
   /* return cache or redirect out to correct map tile */
   if(PeachCache[index]) {
      return (word32 *) &PeachMap[index * PEACHTILELEN];
   } else out = (void *) &PeachMap[index * PEACHTILELEN];
#endif

   /* generaion tile to out */
   peach_generate(index, phash, out);

#ifdef ENABLE_STATIC_PEACH_MAP
   /* flag index as generated */
   PeachCache[index] = 1;
#endif

   return (word32 *) out;
}  /* end peach_generate2solve() */

/* Try solve for a tokenized haiku as nonce output for proof of work.
 * Combine haiku protocols implemented in the Trigg Algorithm with the
 * memory intensive protocols of the Peach algorithm to generate haiku
 * output as proof of work. Place nonce into `out` on success.
 * Return VEOK on success, else VERROR. */
int peach_solve(PEACH_POW *P, void *out)
{
   static size_t SHA256_CTX_SIZE = sizeof(SHA256_CTX);

   SHA256_CTX ictx;
   word32 mario, *tilep, dtile[PEACHTILELEN32];
   word8 hash[SHA256LEN], nonce[SHA256LEN];
   int i;

   /* generate (full) nonce */
   trigg_generate(nonce);
   trigg_generate(nonce + 16);
   /* copy pre-computed SHA256 */
   memcpy(&ictx, &(P->ictx), SHA256_CTX_SIZE);
   /* update pre-computed SHA256 with nonce and finalize */
   sha256_update(&ictx, nonce, SHA256LEN);
   sha256_final(&ictx, hash);
   /* initialize mario's starting index on the map, bound to PEACHCACHELEN */
   for(mario = hash[0], i = 1; i < SHA256LEN; i++) mario *= hash[i];
   mario &= PEACHCACHELEN_M1;
   /* generate tile at index, then determine next jump, for PEACHROUNDS, ... */
   for(i = 0; i < PEACHROUNDS; i++) {
      tilep = peach_generate2solve(mario, P->phash, dtile);
      mario = peach_jump(mario, nonce, tilep);
   } /* ... then generate final tile for hashing */
   tilep = peach_generate2solve(mario, P->phash, dtile);
   /* hash block trailer with final tile */
   sha256_init(&ictx);
   sha256_update(&ictx, hash, SHA256LEN);
   sha256_update(&ictx, tilep, PEACHTILELEN);
   sha256_final(&ictx, hash);
   /* evaluate result against required difficulty */
   if(trigg_eval(hash, P->diff) == VEOK) {
      /* copy successful (full) nonce to `out` */
      memcpy(out, nonce, SHA256LEN);
      return VEOK;
   }

   return VERROR;
}  /* end peach_solve() */


#endif  /* end _CRYPTO_PEACH_C */
