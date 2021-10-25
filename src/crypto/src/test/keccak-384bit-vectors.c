/**
 * Keccak 384-bit vector test.
 *   keccak-384bit-vectors.c (8 September 2021)
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

#define NUMVECTORS    7
#define MAXVECTORLEN  81

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../sha3.h"

#define DIGESTLEN     (KECCAKLEN384)
#define DIGESTHEXLEN  ((KECCAKLEN384 << 1) | 1)

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
   /* Test vectors used in RFC 1321 */
   char rfc_1321_vectors[NUMVECTORS][MAXVECTORLEN] = {
      "",
      "a",
      "abc",
      "message digest",
      "abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "1234567890123456789012345678901234567890123456789012345678901234"
      "5678901234567890"
   };
   /* expected results to test vectors */
   char results[NUMVECTORS][DIGESTHEXLEN] = {
      "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b"
      "2dd2b21362337441ac12b515911957ff",
      "85e964c0843a7ee32e6b5889d50e130e6485cffc826a30167d1dc2b3a0cc79cb"
      "a303501a1eeaba39915f13baab5abacf",
      "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99"
      "f8c681e4afaf31a34db29fb763e3c28e",
      "8a377db088c43e44040a2bfb26676704999d90527913cabff0a3484825daa54d"
      "3061e67da7d836a0805356962af310e8",
      "c5a708ec2178d8c398461547435e482cee0d85de3d75ddbff54e6606a7e9f994"
      "f023a6033b2bf4c516a5f71fc7470d1a",
      "7377c5707506575c26937f3df0d44a773f8c7452c074ee1725c1ab62f741f950"
      "59459d64caebf35a7c247fe28616cab6",
      "fd6e89cbe3271545f94c3e6786803260f929c1589e3091afd58cf32ef53a4f29"
      "b69c1166cb2982e2cb65cf5eb903e669"
   };

   size_t inlen;
   uint8_t digest[DIGESTLEN];
   char *in, hexstr[DIGESTHEXLEN];
   int ecode, ii;

   for (ecode = ii = 0; ii < NUMVECTORS; ii++) {
      DEBUG("hashing vector[%d]... ", ii);
      in = rfc_1321_vectors[ii];
      inlen = strlen(rfc_1321_vectors[ii]);
      memset(digest, 0, DIGESTLEN);
      keccak(in, inlen, digest, DIGESTLEN);
      DEBUG("hash comparison... ");
      digest2hexstr(digest, DIGESTLEN, hexstr);
      if (strncmp(hexstr, results[ii], DIGESTHEXLEN)) {
         DEBUG("fail\n ~      Got: %s\n ~ Expected: %s\n", hexstr, results[ii]);
         ecode |= 1 << ii;
      } else { DEBUG("ok\n"); }
   }

   DEBUG("\n");
   return ecode;
}
