/**
 * Trigg's POW algorithm vectors test.
 *   trigg-vectors.c (25 August 2021)
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

#define NUMVECTORS  5
#define HEXCHARLEN  65

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rand.h"
#include "../trigg.h"

/* Trigg test vectors taken directly from the Mochimo Blockchain Tfile */
uint8_t Tvector[NUMVECTORS][BTSIZE] = {
    {  /* Block 0x1 (1) */
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
   },
   {  /* Block 0xf (15) */
      0x91, 0x08, 0x1b, 0x12, 0xa6, 0xd7, 0x70, 0x9c, 0xa3, 0xb6,
      0x3b, 0x0b, 0x41, 0xa6, 0x09, 0xca, 0x96, 0x6c, 0x99, 0x1c,
      0x7c, 0x4b, 0x7d, 0x66, 0x31, 0xc6, 0xb9, 0xa7, 0xc7, 0xb6,
      0x28, 0x34, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xf4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
      0x00, 0x00, 0x0a, 0xa6, 0x31, 0x5b, 0x0b, 0x00, 0x00, 0x00,
      0x84, 0x42, 0x00, 0x43, 0xf1, 0x12, 0xc0, 0xe8, 0x44, 0x89,
      0xd1, 0x99, 0x04, 0x48, 0xbb, 0xa1, 0xde, 0x17, 0x3c, 0xf9,
      0xaf, 0xd1, 0x33, 0x06, 0x87, 0x63, 0x72, 0x03, 0xe3, 0x51,
      0x0e, 0xa8, 0xfe, 0xee, 0x01, 0x73, 0xda, 0x01, 0x2b, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x52,
      0xf2, 0x01, 0x92, 0x01, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x28, 0xa6, 0x31, 0x5b, 0xe3, 0x11,
      0xad, 0x51, 0xa9, 0xd1, 0x49, 0x04, 0xf3, 0xa9, 0x05, 0x16,
      0xa9, 0x38, 0xbe, 0xd9, 0xb7, 0xa3, 0x96, 0x14, 0x67, 0xc8,
      0x0b, 0x99, 0x4c, 0x71, 0xe5, 0x52, 0xf2, 0x1d, 0x3d, 0x9f
   },
   {  /* Block 0xff (255) */
      0x19, 0x39, 0x13, 0x57, 0x85, 0xf2, 0xff, 0x05, 0xce, 0x12,
      0xff, 0xc7, 0x3b, 0x26, 0xb0, 0x23, 0x80, 0x5e, 0xab, 0xc1,
      0x33, 0x11, 0xa0, 0xee, 0x63, 0x60, 0xc5, 0x56, 0x08, 0x99,
      0xe7, 0xd4, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xf4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
      0x00, 0x00, 0x92, 0xe6, 0x33, 0x5b, 0x22, 0x00, 0x00, 0x00,
      0x5b, 0xc1, 0x60, 0x85, 0x58, 0x11, 0xcf, 0xfa, 0x74, 0x8b,
      0x9f, 0x8a, 0xf3, 0xa3, 0x15, 0x38, 0xcb, 0xa8, 0x1e, 0xf3,
      0x57, 0xba, 0xa1, 0x49, 0xd6, 0xd1, 0xc9, 0x22, 0xdf, 0xf3,
      0xc0, 0xb6, 0x10, 0xd6, 0x01, 0x5d, 0xa7, 0x01, 0x2f, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x0d,
      0xf3, 0xe6, 0x01, 0xea, 0x24, 0x03, 0x01, 0x05, 0x41, 0xf4,
      0x00, 0x00, 0x00, 0x00, 0xf7, 0xe7, 0x33, 0x5b, 0xd3, 0xe0,
      0x9d, 0x5d, 0xd5, 0xb8, 0x7e, 0x92, 0xed, 0x2f, 0xf0, 0x17,
      0xaf, 0xe4, 0xfe, 0x6f, 0x4a, 0xed, 0x84, 0x41, 0x19, 0x63,
      0x74, 0x36, 0x61, 0xd7, 0xab, 0x2e, 0xd4, 0x4b, 0x74, 0x08
   },
   {  /* Block 0xfff (4095) */
      0x27, 0xa2, 0x60, 0xbc, 0x81, 0x9c, 0xbf, 0xc0, 0x93, 0xd9,
      0x1a, 0x23, 0xee, 0x31, 0x2d, 0x73, 0xe2, 0x01, 0xba, 0xb2,
      0x85, 0x39, 0xbd, 0x43, 0xb0, 0x22, 0x89, 0xf0, 0x75, 0x4b,
      0x79, 0x16, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xf4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
      0x00, 0x00, 0x8a, 0xe9, 0x51, 0x5b, 0x26, 0x00, 0x00, 0x00,
      0xc3, 0xf3, 0x9e, 0x6b, 0xc5, 0x98, 0xbb, 0x1d, 0x43, 0xc0,
      0x48, 0x60, 0x3e, 0xb6, 0xff, 0x7d, 0x97, 0xf1, 0x0f, 0x2f,
      0x46, 0x07, 0x65, 0x74, 0xfc, 0xaa, 0xc7, 0xd2, 0x93, 0x20,
      0x50, 0xd6, 0x52, 0xde, 0x01, 0x0e, 0x05, 0x52, 0x8a, 0x03,
      0x01, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x0c,
      0x05, 0x47, 0x83, 0x01, 0xe2, 0x12, 0x03, 0x01, 0x05, 0x3d,
      0x81, 0x00, 0x00, 0x00, 0x05, 0xeb, 0x51, 0x5b, 0x27, 0x40,
      0x28, 0x04, 0x9b, 0x8c, 0x6c, 0x4d, 0xe3, 0x0f, 0xc0, 0x26,
      0x95, 0x11, 0xa2, 0x8a, 0x32, 0xc4, 0x1d, 0x32, 0xd5, 0xa2,
      0x38, 0x61, 0x66, 0xf9, 0x12, 0x9b, 0x25, 0xcd, 0xd5, 0xd3
   },
   {  /* Block 0xffff (65535) */
      0xe3, 0xa1, 0xf3, 0x90, 0x9f, 0x74, 0x12, 0xad, 0x1e, 0x35,
      0xcc, 0x52, 0x6a, 0x0e, 0xe4, 0x9f, 0xa8, 0x88, 0x62, 0xfd,
      0x7e, 0x39, 0x58, 0xd0, 0x33, 0x0e, 0x4b, 0x60, 0x0d, 0x88,
      0x68, 0x78, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xf4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
      0x00, 0x00, 0x4c, 0xab, 0xea, 0x5c, 0x31, 0x00, 0x00, 0x00,
      0x51, 0x37, 0x1b, 0x33, 0xba, 0xca, 0xfd, 0xad, 0x31, 0x93,
      0x6d, 0x16, 0x1e, 0xed, 0x5b, 0xb0, 0xb2, 0x62, 0x25, 0xdb,
      0x03, 0x89, 0x1e, 0x1d, 0x33, 0x16, 0xd5, 0x81, 0xd8, 0x28,
      0xda, 0x40, 0x13, 0x0e, 0x05, 0x6f, 0xf1, 0x01, 0xd6, 0x27,
      0x03, 0x01, 0x05, 0x3e, 0x81, 0x00, 0x00, 0x00, 0x21, 0x0d,
      0x56, 0xd6, 0x01, 0xde, 0x1c, 0x03, 0x01, 0x05, 0x48, 0xd0,
      0x00, 0x00, 0x00, 0x00, 0xc4, 0xab, 0xea, 0x5c, 0xc5, 0x63,
      0x56, 0x1b, 0x00, 0x43, 0x9b, 0x21, 0x41, 0xe9, 0x79, 0xb3,
      0xc3, 0x15, 0x92, 0x9a, 0x34, 0xc5, 0xb3, 0x9a, 0x3a, 0x58,
      0x64, 0xa9, 0xa0, 0x5f, 0x5e, 0x36, 0x09, 0x78, 0x52, 0x1e
   }
};

/* Known hexadecimal results to Tvectors for trigg_checkhash() */
char Tresult[NUMVECTORS][HEXCHARLEN] = {
   "3e01efe149d943fe310e4c3d7bc9ee57e4f0284cd64841b5bb53cf10e67de263",
   "0011eccb02ec8080ebbb823de6754709ec8371a91092a62558206dd66a6331a5",
   "0000000010f48fa0495ab7fd98568f2fd6f1de6163bd624cc1d18c6fa6ecd214",
   "00000000029171d822e115f76fafbf080b203eeb4244fe673402029ccf608f72",
   "0000000000001e0b9eaa26d126c6aeb4077164f2a88547f0514b3ea6b1c70a5d"
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
   BTRAILER bt;
   uint8_t digest[HASHLEN];
   char hexstr[HEXCHARLEN];
   int ecode, ii;

   DEBUG("initialize isolated high speed prng with time(NULL)...\n");
   srand16((uint32_t) time(NULL), 0, 0);

   for (ecode = ii = 0; ii < NUMVECTORS; ii++) {
      DEBUG("load Tvector[%d]... ", ii);
      memcpy(&bt, Tvector[ii], BTSIZE);
      DEBUG("trigg_checkhash()... ");
      memset(digest, 0, HASHLEN);
      trigg_checkhash(&bt, digest);
      DEBUG("hash comparison... ");
      digest2hexstr(digest, HASHLEN, hexstr);
      if (strncmp(hexstr, Tresult[ii], HEXCHARLEN)) {
         DEBUG("fail\n ~      Got: %s\n ~ Expected: %s\n", hexstr, Tresult[ii]);
         ecode |= 1 << ii;
      } else { DEBUG("ok\n"); }
   }

   DEBUG("\n");
   return ecode;
}