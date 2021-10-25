/**
 * trigg.c - Trigg's Proof-of-Work algorithm
 *
 * Copyright (c) 2018-2021 by Adequate Systems, LLC.  All Rights Reserved.
 *
 * For more information, please refer to ../LICENSE
 *
 * Date: 13 October 2018
 * Revised: 27 August 2021
 *
 * Emulate a PDP-10 running MACLISP (circa. 1971)...
 *
 *    Trigg's Algorithm uses classic AI techniques to establish
 *    proof of work.  By expanding a semantic grammar through
 *    heuristic search and combining that with material from the
 *    transaction array, we build the TRIGG chain and solve the
 *    block as evidenced by the output of haiku with the vibe of
 *    Basho...
 *
 *    a raindrop
 *    on sunrise air--
 *    drowned
 *
 * DEPENDENCIES: (referenced as EXTERNAL in GNUmakefile)
 * Repository submodule, c-hashing-algorithms as ../../hash;
 *    ../../hash/src/sha256.c  - 256-bit Secure Hash Algorithm
 *
 * and when ENABLE_THREADSAFE is defined...
 * Repository submodule, c-utilities as ../../util;
 *    ../../util/src/thread.h - multiplatform threading
 *
*/

#ifndef _POW_TRIGG_C_
#define _POW_TRIGG_C_  /* include guard */


#include "trigg.h"
#include "rand.h"

static DICT Dict[MAXDICT] = {
/* Adverbs and function words */
   { "NIL", 0 },
   { "\n", F_OP },
   { "\b:", F_OP },
   { "\b--", F_OP },
   { "like", F_OP },
   { "a", F_OP },
   { "the", F_OP },
   { "of", F_OP },
   { "no", F_OP },
   { "\bs", F_OP },
   { "after", F_OP },
   { "before", F_OP },
/* Prepositions */
   { "at", F_PREP },
   { "in", F_PREP },
   { "on", F_PREP },
   { "under", F_PREP },
   { "above", F_PREP },
   { "below", F_PREP },
/* Verbs - intransitive ING and MOTION */
   { "arriving", F_ING | F_MOTION },
   { "departing", F_ING | F_MOTION },
   { "going", F_ING | F_MOTION },
   { "coming", F_ING | F_MOTION },
   { "creeping", F_ING | F_MOTION },
   { "dancing", F_ING | F_MOTION },
   { "riding", F_ING | F_MOTION },
   { "strutting", F_ING | F_MOTION },
   { "leaping", F_ING | F_MOTION },
   { "leaving", F_ING | F_MOTION },
   { "entering", F_ING | F_MOTION },
   { "drifting", F_ING | F_MOTION },
   { "returning", F_ING | F_MOTION },
   { "rising", F_ING | F_MOTION },
   { "falling", F_ING | F_MOTION },
   { "rushing", F_ING | F_MOTION },
   { "soaring", F_ING | F_MOTION },
   { "travelling", F_ING | F_MOTION },
   { "turning", F_ING | F_MOTION },
   { "singing", F_ING | F_MOTION },
   { "walking", F_ING | F_MOTION },
/* Verbs - intransitive ING */
   { "crying", F_ING },
   { "weeping", F_ING },
   { "lingering", F_ING },
   { "pausing", F_ING },
   { "shining", F_ING },
/* --- motion intransitive infinitive */
   { "fall", F_INF | F_MOTION },
   { "flow", F_INF | F_MOTION },
   { "wander", F_INF | F_MOTION },
   { "disappear", F_INF | F_MOTION },
/* --- intransitive infinitive */
   { "wait", F_INF },
   { "bloom", F_INF },
   { "doze", F_INF },
   { "dream", F_INF },
   { "laugh", F_INF },
   { "meditate", F_INF },
   { "listen", F_INF },
   { "sing", F_INF },
   { "decay", F_INF },
   { "cling", F_INF },
   { "grow", F_INF },
   { "forget", F_INF },
   { "remain", F_INF },
/* Adjectives - physical */
/* valences (e) based on Osgood's evaluation factor */
   { "arid", F_ADJ },
   { "abandoned", F_ADJ },
   { "aged", F_ADJ },
   { "ancient", F_ADJ },
   { "full", F_ADJ },
   { "glorious", F_ADJ },
   { "good", F_ADJ },
   { "beautiful", F_ADJ },
   { "first", F_ADJ },
   { "last", F_ADJ },
   { "forsaken", F_ADJ },
   { "sad", F_ADJ },
   { "mandarin", F_ADJ },
   { "naked", F_ADJ },
   { "nameless", F_ADJ },
   { "old", F_ADJ },
/* Ambient adjectives */
   { "quiet", F_ADJ | F_AMB },
   { "peaceful", F_ADJ },
   { "still", F_ADJ },
   { "tranquil", F_ADJ },
   { "bare", F_ADJ },
/* Time interval adjectives or nouns */
   { "evening", F_ADJ | F_TIMED },
   { "morning", F_ADJ | F_TIMED },
   { "afternoon", F_ADJ | F_TIMED },
   { "spring", F_ADJ | F_TIMEY },
   { "summer", F_ADJ | F_TIMEY },
   { "autumn", F_ADJ | F_TIMEY },
   { "winter", F_ADJ | F_TIMEY },
/* Adjectives - physical */
   { "broken", F_ADJ },
   { "thick", F_ADJ },
   { "thin", F_ADJ },
   { "little", F_ADJ },
   { "big", F_ADJ },
/* Physical + ambient adjectives */
   { "parched", F_ADJ | F_AMB },
   { "withered", F_ADJ | F_AMB },
   { "worn", F_ADJ | F_AMB },
/* Physical adj -- material things */
   { "soft", F_ADJ },
   { "bitter", F_ADJ },
   { "bright", F_ADJ },
   { "brilliant", F_ADJ },
   { "cold", F_ADJ },
   { "cool", F_ADJ },
   { "crimson", F_ADJ },
   { "dark", F_ADJ },
   { "frozen", F_ADJ },
   { "grey", F_ADJ },
   { "hard", F_ADJ },
   { "hot", F_ADJ },
   { "scarlet", F_ADJ },
   { "shallow", F_ADJ },
   { "sharp", F_ADJ },
   { "warm", F_ADJ },
   { "close", F_ADJ },
   { "calm", F_ADJ },
   { "cruel", F_ADJ },
   { "drowned", F_ADJ },
   { "dull", F_ADJ },
   { "dead", F_ADJ },
   { "sick", F_ADJ },
   { "deep", F_ADJ },
   { "fast", F_ADJ },
   { "fleeting", F_ADJ },
   { "fragrant", F_ADJ },
   { "fresh", F_ADJ },
   { "loud", F_ADJ },
   { "moonlit", F_ADJ | F_AMB },
   { "sacred", F_ADJ },
   { "slow", F_ADJ },
/* Nouns top-level */
/* Humans */
   { "traveller", F_NS },
   { "poet", F_NS },
   { "beggar", F_NS },
   { "monk", F_NS },
   { "warrior", F_NS },
   { "wife", F_NS },
   { "courtesan", F_NS },
   { "dancer", F_NS },
   { "daemon", F_NS },
/* Animals */
   { "frog", F_NS },
   { "hawks", F_NPL },
   { "larks", F_NPL },
   { "cranes", F_NPL },
   { "crows", F_NPL },
   { "ducks", F_NPL },
   { "birds", F_NPL },
   { "skylark", F_NS },
   { "sparrows", F_NPL },
   { "minnows", F_NPL },
   { "snakes", F_NPL },
   { "dog", F_NS },
   { "monkeys", F_NPL },
   { "cats", F_NPL },
   { "cuckoos", F_NPL },
   { "mice", F_NPL },
   { "dragonfly", F_NS },
   { "butterfly", F_NS },
   { "firefly", F_NS },
   { "grasshopper", F_NS },
   { "mosquitos", F_NPL },
/* Plants */
   { "trees", F_NPL | F_IN | F_AT },
   { "roses", F_NPL },
   { "cherries", F_NPL },
   { "flowers", F_NPL },
   { "lotuses", F_NPL },
   { "plums", F_NPL },
   { "poppies", F_NPL },
   { "violets", F_NPL },
   { "oaks", F_NPL | F_AT },
   { "pines", F_NPL | F_AT },
   { "chestnuts", F_NPL },
   { "clovers", F_NPL },
   { "leaves", F_NPL },
   { "petals", F_NPL },
   { "thorns", F_NPL },
   { "blossoms", F_NPL },
   { "vines", F_NPL },
   { "willows", F_NPL },
/* Things */
   { "mountain", F_NS | F_AT | F_ON },
   { "moor", F_NS | F_AT | F_ON | F_IN },
   { "sea", F_NS | F_AT | F_ON | F_IN },
   { "shadow", F_NS | F_IN },
   { "skies", F_NPL | F_IN },
   { "moon", F_NS },
   { "star", F_NS },
   { "stone", F_NS },
   { "cloud", F_NS },
   { "bridge", F_NS | F_ON | F_AT },
   { "gate", F_NS | F_AT },
   { "temple", F_NS | F_IN | F_AT },
   { "hovel", F_NS | F_IN | F_AT },
   { "forest", F_NS | F_IN | F_AT },
   { "grave", F_NS | F_IN | F_AT | F_ON },
   { "stream", F_NS | F_IN | F_AT | F_ON },
   { "pond", F_NS | F_IN | F_AT | F_ON },
   { "island", F_NS | F_ON | F_AT },
   { "bell", F_NS },
   { "boat", F_NS | F_IN | F_ON },
   { "sailboat", F_NS | F_IN | F_ON },
   { "bon fire", F_NS | F_AT },
   { "straw mat", F_NS | F_ON },
   { "cup", F_NS | F_IN },
   { "nest", F_NS | F_IN },
   { "sun", F_NS | F_IN },
   { "village", F_NS | F_IN },
   { "tomb", F_NS | F_IN | F_AT },
   { "raindrop", F_NS | F_IN },
   { "wave", F_NS | F_IN },
   { "wind", F_NS | F_IN },
   { "tide", F_NS | F_IN | F_AT },
   { "fan", F_NS },
   { "hat", F_NS },
   { "sandal", F_NS },
   { "shroud", F_NS },
   { "pole", F_NS },
/* Mass - substance */
   { "water", F_ON | F_IN | F_MASS | F_AMB },
   { "air", F_ON | F_IN | F_MASS | F_AMB },
   { "mud", F_ON | F_IN | F_MASS | F_AMB },
   { "rain", F_IN | F_MASS | F_AMB },
   { "thunder", F_IN | F_MASS | F_AMB },
   { "ice", F_ON | F_IN | F_MASS | F_AMB },
   { "snow", F_ON | F_IN | F_MASS | F_AMB },
   { "salt", F_ON | F_IN | F_MASS },
   { "hail", F_IN | F_MASS | F_AMB },
   { "mist", F_IN | F_MASS | F_AMB },
   { "dew", F_IN | F_MASS | F_AMB },
   { "foam", F_IN | F_MASS | F_AMB },
   { "frost", F_IN | F_MASS | F_AMB },
   { "smoke", F_IN | F_MASS | F_AMB },
   { "twilight", F_IN | F_AT | F_MASS | F_AMB },
   { "earth", F_ON | F_IN | F_MASS },
   { "grass", F_ON | F_IN | F_MASS },
   { "bamboo", F_MASS },
   { "gold", F_MASS },
   { "grain", F_MASS },
   { "rice", F_MASS },
   { "tea", F_IN | F_MASS },
   { "light", F_IN | F_MASS | F_AMB },
   { "darkness", F_IN | F_MASS | F_AMB },
   { "firelight", F_IN | F_MASS | F_AMB },
   { "sunlight", F_IN | F_MASS | F_AMB },
   { "sunshine", F_IN | F_MASS | F_AMB },
/* Abstract nouns and acts */
   { "journey", F_NS | F_ON },
   { "serenity", F_MASS },
   { "dusk", F_TIMED },
   { "glow", F_NS },
   { "scent", F_NS },
   { "sound", F_NS },
   { "silence", F_NS },
   { "voice", F_NS },
   { "day", F_NS | F_TIMED },
   { "night", F_NS | F_TIMED },
   { "sunrise", F_NS | F_TIMED },
   { "sunset", F_NS | F_TIMED },
   { "midnight", F_NS | F_TIMED },
   { "equinox", F_NS | F_TIMEY },
   { "noon", F_NS | F_TIMED }
};  /* end Dict[] */

/* Case frames for the semantic grammar with a vibe inspired by Basho... */
static uint32_t Frame[NFRAMES][MAXH] = {
   {
      F_PREP, F_ADJ, F_MASS, S_NL,            /* on a quiet moor */
      F_NPL, S_NL,                            /* raindrops       */
      F_INF | F_ING                           /* fall            */
   },
   {
      F_PREP, F_MASS, S_NL,
      F_ADJ, F_NPL, S_NL,
      F_INF | F_ING
   },
   {
      F_PREP, F_TIMED, S_NL,
      F_ADJ, F_NPL, S_NL,
      F_INF | F_ING
   },
   {
      F_PREP, F_TIMED, S_NL,
      S_A, F_NS, S_NL,
      F_ING
   },
   {
      F_TIME, F_AMB, S_NL,                    /* morning mist      */
      F_PREP, S_A, F_ADJ, F_NS, S_MD, S_NL,   /* on a worn field-- */
      F_ADJ | F_ING                           /* red               */
   },
   {
      F_TIME, F_AMB, S_NL,
      F_ADJ, F_MASS, S_NL,
      F_ING
   },
   {
      F_TIME, F_MASS, S_NL,                   /* morning mist */
      F_INF, S_S, S_CO, S_NL,                 /* remains:     */
      F_AMB                                   /* smoke        */
   },
   {
      F_ING, F_PREP, S_A, F_ADJ, F_NS, S_NL,  /* arriving at a parched gate */
      F_MASS, F_ING, S_MD, S_NL,              /* mist rises--               */
      S_A, F_ADJ, F_NS                        /* a moonlit sandal           */
   },
   {
      F_ING, F_PREP, F_TIME, F_MASS, S_NL,    /* pausing under a hot tomb */
      F_MASS, F_ING, S_MD, S_NL,              /* firelight shining--      */
      S_A, F_ADJ, F_NS                        /* a beautiful bon fire     */
   },
   {
      S_A, F_NS, S_NL,                        /* a wife              */
      F_PREP, F_TIMED, F_MASS, S_MD, S_NL,    /* in afternoon mist-- */
      F_ADJ                                   /* sad                 */
   }, /* ! increment NFRAMES if adding more frames... */
};

/* Generate a tokenized haiku into `out` using the embedded prng. */
void *trigg_generate(void *out)
{
   uint32_t *fp;
   uint8_t *tp;
   int j, widx;

   /* choose a random haiku frame to fill */
   fp = &Frame[rand16() % NFRAMES][0];
   for (j = 0, tp = (uint8_t *) out; j < MAXH; j++, fp++, tp++) {
      if (*fp == 0) {
         /* zero fill to end of available token space */
         *tp = 0;
         continue;
      }
      if (*fp & F_XLIT) {
         /* force S_* type semantic feature where required by frame */
         widx = *fp & 255;
      } else {
         do { /* randomly select next word suitable for frame */
            widx = rand16() & MAXDICT_M1;
         } while ((Dict[widx].fe & *fp) == 0);
      }
      *tp = (uint8_t) widx;
   }

   return out;
}

/* Expand a haiku to character format.
 * It must have the correct syntax and vibe. */
char *trigg_expand(void *nonce, void *haiku)
{
   uint8_t *np, *bp, *bpe, *wp;
   int i;

   np = (uint8_t *) nonce;
   bp = (uint8_t *) haiku;
   bpe = bp + HAIKUCHARLEN;
   /* step through all nonce values */
   for (i = 0; i < MAXH; i++, np++) {
      if (*np == 0) break;
      /* place word from dictionary into bp */
      wp = Dict[*np].tok;
      while (*wp) *(bp++) = *(wp++);
      if (bp[-1] != '\n') *(bp++) = ' ';
   }
   /* zero fill remaining character space */
   i = (bpe - bp) & 7;
   while (i--) *(bp++) = 0;  /* 8-bit fill */
   while (bp < bpe) {  /* 64-bit fill */
      *((uint64_t *) bp) = 0;
      bp += 8;
   }

   return (char *) haiku;
}

/* Evaluate the TRIGG chain by using a heuristic estimate of the
 * final solution cost (Nilsson, 1971). Evaluate the relative
 * distance within the TRIGG chain to validate proof of work.
 * Return VEOK if passed, else VERROR. */
int trigg_eval(void *hash, uint8_t diff)
{
   uint8_t *bp, n;

   n = diff >> 3;
   /* coarse check required bytes are zero */
   for (bp = (uint8_t *) hash; n; n--) {
      if(*(bp++) != 0) return VERROR;
   }
   if ((diff & 7) == 0) return VEOK;
   /* fine check required bits are zero */
   if ((*bp & ~(0xff >> (diff & 7))) != 0) {
      return VERROR;
   }

   return VEOK;
}

/* Check haiku syntax against semantic grammar.
 * It must have the correct syntax, semantics, and vibe.
 * Return VEOK on correct syntax, else VERROR. */
int trigg_syntax(void *nonce)
{
   uint32_t sf[MAXH], *fp;
   uint8_t *np;
   int j;

   /* load semantic frame associated with nonce */
   for (j = 0, np = (uint8_t *) nonce; j < MAXH; j++) sf[j] = Dict[np[j]].fe;
   /* check input for respective semantic features, use unification on sets. */
   for (fp = &Frame[0][0]; fp < &Frame[NFRAMES][0]; fp += MAXH) {
      for (j = 0; j < MAXH; j++) {
         if (fp[j] == 0) {
            if (sf[j] == 0) return VEOK;
            break;
         }
         if (fp[j] & F_XLIT) {
            if ((fp[j] & 255) != np[j]) break;
            continue;
         }
         if ((sf[j] & fp[j]) == 0) break;
      }
      if (j >= MAXH) return VEOK;
   }

   return VERROR;
}

/* Check proof of work. The haiku must be syntactically correct
 * and have the right vibe. Also, entropy MUST match difficulty.
 * If non-NULL, place final hash in `out` on success.
 * Return VEOK on success, else VERROR. */
#define trigg_check(btp)  trigg_checkhash(btp, NULL)
int trigg_checkhash(BTRAILER *bt, void *out)
{
   SHA256_CTX ictx;
   uint8_t haiku[HAIKUCHARLEN], hash[SHA256LEN];

   /* check syntax, semantics, and vibe... */
   if (trigg_syntax(bt->nonce) == VERROR) return VERROR;
   if (trigg_syntax(bt->nonce + 16) == VERROR) return VERROR;
   /* re-linearise the haiku */
   trigg_expand(bt->nonce, haiku);
   /* obtain entropy */
   sha256_init(&ictx);
   sha256_update(&ictx, bt->mroot, HASHLEN);
   sha256_update(&ictx, haiku, HAIKUCHARLEN);
   sha256_update(&ictx, bt->nonce + 16, 16);
   sha256_update(&ictx, bt->bnum, 8);
   sha256_final(&ictx, hash);
   /* pass final hash to `out` if not NULL */
   if (out != NULL) memcpy(out, hash, SHA256LEN);
   /* return evaluation */
   return trigg_eval(hash, bt->difficulty[0]);
}

/* Prepare a TRIGG context for solving. */
void trigg_init(TRIGG_POW *T, BTRAILER *bt)
{
   /* add merkle root and bnum to Tchain */
   memcpy(T->mroot, bt->mroot, HASHLEN);
   memcpy(T->bnum, bt->bnum, 8);
   /* place required difficulty in diff */
   T->diff = bt->difficulty[0];
}

/* Try solve for a tokenized haiku as nonce output for proof of work.
 * Create the haiku inside the TRIGG chain using a semantic grammar
 * (Burton, 1976). The output must pass syntax checks, the entropy
 * check, and have the right vibe. Entropy is always preserved at
 * high difficulty levels. Place nonce into `out` on success.
 * Return VEOK on success, else VERROR. */
int trigg_solve(TRIGG_POW *T, void *out)
{
   uint8_t hash[SHA256LEN];

   /* generate (full) nonce */
   trigg_generate(T->nonce2);
   trigg_generate(T->nonce1);
   /* expand shifted nonce into the TRIGG chain! */
   trigg_expand(T->nonce1, T->haiku);
   /* perform SHA256 hash on TRIGG chain */
   sha256(T, TCHAINLEN, hash);
   /* evaluate result against required difficulty */
   if (trigg_eval(hash, T->diff) == VEOK) {
      /* copy successful (full) nonce to `out` */
      uint8_t *bp = (uint8_t *) out;
      memcpy(bp, T->nonce1, 16);
      memcpy(bp + 16, T->nonce2, 16);
      return VEOK;
   }

   return VERROR;
}


#endif  /* end _POW_TRIGG_C_ */
