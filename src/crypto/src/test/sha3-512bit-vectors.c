/**
 * SHA3 512-bit vector test.
 *   sha3-512bit-vectors.c (8 September 2021)
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

#define DIGESTLEN     (SHA3LEN512)
#define DIGESTHEXLEN  ((SHA3LEN512 << 1) | 1)

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
      "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
      "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
      "697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa80"
      "3f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a",
      "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
      "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
      "3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141"
      "ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59",
      "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384"
      "eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68",
      "d1db17b4745b255e5eb159f66593cc9c143850979fc7a3951796aba80165aab5"
      "36b46174ce19e3f707f0e5c6487f5f03084bc0ec9461691ef20113e42ad28163",
      "9524b9a5536b91069526b4f6196b7e9475b4da69e01f0c855797f224cd7335dd"
      "b286fd99b9b32ffe33b59ad424cc1744f6eb59137f5fb8601932e8a8af0ae930"
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
