/**
 * KECCAK 512-bit vector test.
 *   keccak-512bit-vectors.c (8 September 2021)
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

#define DIGESTLEN     (KECCAKLEN512)
#define DIGESTHEXLEN  ((KECCAKLEN512 << 1) | 1)

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
      "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
      "c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
      "9c46dbec5d03f74352cc4a4da354b4e9796887eeb66ac292617692e765dbe400"
      "352559b16229f97b27614b51dbfbbb14613f2c10350435a8feaf53f73ba01c7c",
      "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5"
      "d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
      "cccc49fa63822b00004cf6c889b28a035440ffb3ef50e790599935518e2aefb0"
      "e2f1839170797f7763a5c43b2dcf02abf579950e36358d6d04dfddc2abac7545",
      "e55bdca64dfe33f36ae3153c727833f9947d92958073f4dd02e38a82d8acb282"
      "b1ee1330a68252a54c6d3d27306508ca765acd45606caeaf51d6bdc459f551f1",
      "d5fa6b93d54a87bbde52dbb44daf96a3455daef9d60cdb922bc4b72a5bbba97c"
      "5bf8c59816fede302fc64e98ce1b864df7be671c968e43d1bae23ad76a3e702d",
      "bc08a9a245e99f62753166a3226e874896de0914565bee0f8be29d678e0da66c"
      "508cc9948e8ad7be78eaa4edced482253f8ab2e6768c9c8f2a2f0afff083d51c"
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
