/**
 * Blake2b 384-bit (keyed) vector test.
 *   blake2b-384bit-keyed-vectors.c (6 September 2021)
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

#define DIGESTLEN     (BLAKE2BLEN384)
#define DIGESTHEXLEN  ((BLAKE2BLEN384 << 1) | 1)

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
      "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd324"
      "4a6caf0498812673c5e05ef583825100",
      "a340aaff16b65ded203e4410216086161ac5d54fa08f2fc71414315df4b76e4b"
      "4e9ab2c5a87f79d07dd3328e8a16268f",
      "e3c90280c534a46f7dd230cbe7f4fa62ee3e47a3f0ade5b732aedbeeeaee7b7b"
      "a4af1a3a3fe63726cd23bee5e36496b1",
      "9ba17065ebe1bf6323c230148309556c01718c068227d4b6b4b2d17f8102b69a"
      "1fc456c7e130c0112acb34b93bd7103b",
      "8fb50610eb28616cd21d51fac1cd1b3dbbf9887a5d77fdcab71712abb3210731"
      "13bef56a2ece02a1ec56d38a7ad24aaa",
      "a6f86d87afd57d947335d4fecc786113641ccdc2a0ece2ad67cac958b7d59e5b"
      "72dec073375266ab7ff1a7640f5f6bb1",
      "0000000000000000000000000000000000000000000000000000000000000000"
      "00000000000000000000000000000000"
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
      blake2b(in, inlen, in, inlen, digest, DIGESTLEN);
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
