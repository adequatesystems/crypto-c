/**
 * Blake2b 512-bit (keyed) vector test.
 *   blake2b-512bit-keyed-vectors.c (6 September 2021)
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

#define DIGESTLEN     (BLAKE2BLEN512)
#define DIGESTHEXLEN  ((BLAKE2BLEN512 << 1) | 1)

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
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
      "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
      "bf829aab39c6e3d4bc98a1d6dc467d46ec16ea28979629d915ed2574d5fff0a9"
      "3db5042fc5ea3eaae572b02bee6e6ab1faa44b07c9fe6709b9985f51d043c7a1",
      "17de517e1278d00ac7a6bcf048881aa9a972e6b5cef843d3c61d3e252068a2f5"
      "26c999f45cd96b172509d085b59170e388f845750c812781df582be3fc4a1972",
      "8f6de0600e70979094ab83af161c60a7fff7729e489e398cc3e9074e3dd33f0a"
      "c91a24dab30491262c87019534653a63b1ccbf0d5d468e83b12b6fc7a3b6dd98",
      "ca43505c2ea6e708ef22dd66ac069fd0497d11f823897e18ed516095bd493e70"
      "f0b6008ecf70ee0c10830575fe326280721a7af707fdaa11b0bc9ffba5925845",
      "2a0cdf013a4c81bfb2d43318ceb5080383ed631f067793539b478a7b7ca2d846"
      "288da45f9830024c2cd7f243eec677138e204b4baf751f15bf490e3d8e6d6806",
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
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
