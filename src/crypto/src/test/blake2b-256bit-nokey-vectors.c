/**
 * Blake2b 256-bit (no key) vector test.
 *   blake2b-256bit-nokey-vectors.c (6 September 2021)
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

#include "../blake2b.h"

#define DIGESTLEN     (BLAKE2BLEN256)
#define DIGESTHEXLEN  ((BLAKE2BLEN256 << 1) | 1)

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
      "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
      "8928aae63c84d87ea098564d1e03ad813f107add474e56aedd286349c0c03ea4",
      "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
      "31a65b562925c6ffefdafa0ad830f4e33eff148856c2b4754de273814adf8b85",
      "117ad6b940f5e8292c007d9c7e7350cd33cf85b5887e8da71c7957830f536e7c",
      "63f74bf0df57c4fd10f949edbe1cb7f6e374ecab882616381d6d999fda748b93",
      "a4705bbca1ae2e7a5d184a403a15f36c31c7e567adeae33f0f3e2f3ca9958198"
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
      blake2b(in, inlen, NULL, 0, digest, DIGESTLEN);
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
