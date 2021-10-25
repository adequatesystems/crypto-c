/**
 * SHA256 vector test.
 *   sha256-vectors.c (8 September 2021)
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

#include "../sha256.h"

#define DIGESTLEN     (SHA256LEN)
#define DIGESTHEXLEN  ((SHA256LEN << 1) | 1)

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
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
      "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
      "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
      "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"
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
      sha256(in, inlen, digest);
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
