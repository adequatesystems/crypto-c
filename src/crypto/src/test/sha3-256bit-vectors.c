/**
 * SHA3 256-bit vector test.
 *   sha3-256bit-vectors.c (8 September 2021)
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

#define DIGESTLEN     (SHA3LEN256)
#define DIGESTHEXLEN  ((SHA3LEN256 << 1) | 1)

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
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
      "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
      "edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd",
      "7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521",
      "a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f",
      "293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d"
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
      sha3(in, inlen, digest, DIGESTLEN);
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
