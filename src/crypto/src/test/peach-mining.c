/**
 * Peach POW algorithm mining test.
 *   peach-mining.c (25 August 2021)
 *
 * Copyright (c) 2021 Adequate Systems, LLC. All Rights Reserved.
 *
 * For more information, please refer to ../../LICENSE
 * 
 */


/* _CRT_SECURE_NO_WARNINGS must be defined before includes to be effective */
#define _CRT_SECURE_NO_WARNINGS  /* Suppresses Windows CRT warnings */

#ifdef DEBUG
#undef DEBUG
#define DEBUG(fmt, ...)  printf(fmt, ##__VA_ARGS__)
#else
#undef DEBUG
#define DEBUG(fmt, ...)  /* do nothing */
#endif

#define MINDIFF     6
#define MAXDIFF     10
#define MAXDELTA    10.0f
#define MAXCHARLEN  256

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "rand.h"
#include "../peach.h"

/* Metric prefix array */
char MetricPrefix[9][3] = { "", "K", "M", "G", "T", "P", "E", "Z", "Y" };

/* Block 0x1 trailer data taken directly from the Mochimo Blockchain Tfile */
uint8_t Block1[BTSIZE] = {
   0x00, 0x17, 0x0c, 0x67, 0x11, 0xb9, 0xdc, 0x3c, 0xa7, 0x46,
   0xc4, 0x6c, 0xc2, 0x81, 0xbc, 0x69, 0xe3, 0x03, 0xdf, 0xad,
   0x2f, 0x33, 0x3b, 0xa3, 0x97, 0xba, 0x06, 0x1e, 0xcc, 0xef,
   0xde, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0xf4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
   0xf7, 0x2d, 0x1f, 0xae, 0xa8, 0x7f, 0x5b, 0x8f, 0x3c, 0xa9,
   0xce, 0x6c, 0xdd, 0x5a, 0xe6, 0xf1, 0xb0, 0x81, 0xe5, 0x70,
   0xc1, 0xf8, 0xe9, 0x63, 0x90, 0xb1, 0x25, 0x38, 0x8e, 0x48,
   0x46, 0x73, 0x10, 0xf9, 0x01, 0x05, 0xf1, 0x01, 0x26, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0xdf,
   0x01, 0x11, 0x05, 0x4b, 0xb7, 0x03, 0x01, 0x56, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0xb1, 0x0d, 0x31, 0x5b, 0x78, 0x49,
   0x1f, 0x37, 0xaa, 0xa7, 0x54, 0xef, 0x7d, 0xb8, 0x1a, 0x96,
   0x42, 0xd4, 0xba, 0x1c, 0xf7, 0x2f, 0x6e, 0x37, 0xff, 0x92,
   0x99, 0x9a, 0xa0, 0x32, 0x55, 0x51, 0xbc, 0xf1, 0x5f, 0x69
};

/* Interpret digest "in" as hexadecimal char array, placed in "out" */
void digest2hexstr(void *in, size_t inlen, char *out)
{
   uint8_t *bp = (uint8_t *) in;

   for (size_t ii = 0; ii < inlen; ii++) {
      sprintf(&out[ii * 2], "%02x", *bp++);
   } /* force last character as nul byte character */
   out[inlen * 2] = '\0';
}


int main()
{
   PEACH_POW P;
   BTRAILER bt;
   clock_t start, solve;
   uint8_t diff, digest[HASHLEN];
   char hexstr[MAXCHARLEN];
   float delta, hps;
   int ecode, n;

   DEBUG("initialize isolated high speed prng...\n");
   srand16((uint32_t) time(NULL), 0, 0);
   ecode = delta = hps = n = 0;
   DEBUG("load block trailer from Block1[]...\n");
   memcpy(&bt, Block1, BTSIZE);
   start = clock(); /* record start timestamp */
   /* increment difficulty until solve time hits 1 second */
   for (diff = 1; diff < MAXDIFF && delta < MAXDELTA; diff++) {
      DEBUG("(re)initialize algorithm for diff %u...\n", (unsigned) diff);
      bt.difficulty[0] = P.diff = diff; /* update block trailer with diff */
      solve = clock(); /* record solve timestamp */
      /* initialize Peach context; solve Peach; increment hash attempts */
      for(peach_init(&P, &bt); peach_solve(&P, bt.nonce); n++);
      /* calculate time taken to produce solve */
      delta = (float) (clock() - solve) / (float) CLOCKS_PER_SEC;
      /* ensure solution is correct */
      if (peach_checkhash(&bt, digest)) {
         DEBUG("peach_check() failed, diff= %u\n", P.diff);
         digest2hexstr(digest, HASHLEN, hexstr);
         DEBUG(" ~ HASH: %s\n", hexstr);
         digest2hexstr(bt.nonce, HASHLEN, hexstr);
         DEBUG(" ~ NONCE: %s\n", hexstr);
         trigg_expand(bt.nonce, hexstr);
         DEBUG(" ~ HAIKU:\n\n%s\n", hexstr);
         ecode = diff;
         break;
      }
   }
   /* calculate time taken to perform tests */
   delta = (float) (clock() - start) / (float) CLOCKS_PER_SEC;
   /* calculate performance of algorithm */
   if (delta > 0) {
      hps = (float) n / delta;
      n = hps ? (log10f(hps) / 3) : 0;
      if (n > 0) hps /= powf(2, 10) * n;
      DEBUG("\nPerformance: ~%u %sH/s\n", (unsigned) hps, MetricPrefix[n]);
   } else {
      DEBUG("\n***Performance calculation results in divide by Zero!\n");
   }
   /* check difficulty met requirement */
   if (diff < MINDIFF) {
      DEBUG("\n***Difficulty requirement (%u) was not met!\n", MINDIFF);
      ecode |= 0x80;
   }

   DEBUG("\n");
   return ecode;
}
