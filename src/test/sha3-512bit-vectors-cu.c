
/* must be declared before includes */
#ifndef CUDA
   #define CUDA
#endif

#include <stdint.h>
#include "_assert.h"
#include "../sha3.h"

#define NUMVECTORS    7
#define MAXVECTORLEN  81
#define DIGESTLEN     SHA3LEN512

/* Test vectors used in RFC 1321 */
static char rfc_1321_vectors[NUMVECTORS][MAXVECTORLEN] = {
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
static uint8_t expect[NUMVECTORS][DIGESTLEN] = {
   {
      0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67,
      0xdc, 0x18, 0x5a, 0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2,
      0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6, 0x15,
      0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40,
      0x2c, 0x3a, 0xc5, 0x58, 0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3,
      0xe3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26
   },
   {
      0x69, 0x7f, 0x2d, 0x85, 0x61, 0x72, 0xcb, 0x83, 0x09, 0xd6, 0xb8,
      0xb9, 0x7d, 0xac, 0x4d, 0xe3, 0x44, 0xb5, 0x49, 0xd4, 0xde, 0xe6,
      0x1e, 0xdf, 0xb4, 0x96, 0x2d, 0x86, 0x98, 0xb7, 0xfa, 0x80, 0x3f,
      0x4f, 0x93, 0xff, 0x24, 0x39, 0x35, 0x86, 0xe2, 0x8b, 0x5b, 0x95,
      0x7a, 0xc3, 0xd1, 0xd3, 0x69, 0x42, 0x0c, 0xe5, 0x33, 0x32, 0x71,
      0x2f, 0x99, 0x7b, 0xd3, 0x36, 0xd0, 0x9a, 0xb0, 0x2a
   },
   {
      0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93, 0xcd,
      0x92, 0x4b, 0x6b, 0x09, 0x6e, 0x08, 0xf6, 0x21, 0x82, 0x74, 0x44,
      0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e, 0x10,
      0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9, 0x1a, 0x7e, 0xc5, 0x76,
      0x47, 0xe3, 0x93, 0x40, 0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5,
      0xa5, 0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
   },
   {
      0x34, 0x44, 0xe1, 0x55, 0x88, 0x1f, 0xa1, 0x55, 0x11, 0xf5, 0x77,
      0x26, 0xc7, 0xd7, 0xcf, 0xe8, 0x03, 0x02, 0xa7, 0x43, 0x30, 0x67,
      0xb2, 0x9d, 0x59, 0xa7, 0x14, 0x15, 0xca, 0x9d, 0xd1, 0x41, 0xac,
      0x89, 0x2d, 0x31, 0x0b, 0xc4, 0xd7, 0x81, 0x28, 0xc9, 0x8f, 0xda,
      0x83, 0x9d, 0x18, 0xd7, 0xf0, 0x55, 0x6f, 0x2f, 0xe7, 0xac, 0xb3,
      0xc0, 0xcd, 0xa4, 0xbf, 0xf3, 0xa2, 0x5f, 0x5f, 0x59
   },
   {
      0xaf, 0x32, 0x8d, 0x17, 0xfa, 0x28, 0x75, 0x3a, 0x3c, 0x9f, 0x5c,
      0xb7, 0x2e, 0x37, 0x6b, 0x90, 0x44, 0x0b, 0x96, 0xf0, 0x28, 0x9e,
      0x57, 0x03, 0xb7, 0x29, 0x32, 0x4a, 0x97, 0x5a, 0xb3, 0x84, 0xed,
      0xa5, 0x65, 0xfc, 0x92, 0xaa, 0xde, 0xd1, 0x43, 0x66, 0x99, 0x00,
      0xd7, 0x61, 0x86, 0x16, 0x87, 0xac, 0xdc, 0x0a, 0x5f, 0xfa, 0x35,
      0x8b, 0xd0, 0x57, 0x1a, 0xaa, 0xd8, 0x0a, 0xca, 0x68
   },
   {
      0xd1, 0xdb, 0x17, 0xb4, 0x74, 0x5b, 0x25, 0x5e, 0x5e, 0xb1, 0x59,
      0xf6, 0x65, 0x93, 0xcc, 0x9c, 0x14, 0x38, 0x50, 0x97, 0x9f, 0xc7,
      0xa3, 0x95, 0x17, 0x96, 0xab, 0xa8, 0x01, 0x65, 0xaa, 0xb5, 0x36,
      0xb4, 0x61, 0x74, 0xce, 0x19, 0xe3, 0xf7, 0x07, 0xf0, 0xe5, 0xc6,
      0x48, 0x7f, 0x5f, 0x03, 0x08, 0x4b, 0xc0, 0xec, 0x94, 0x61, 0x69,
      0x1e, 0xf2, 0x01, 0x13, 0xe4, 0x2a, 0xd2, 0x81, 0x63
   },
   {
      0x95, 0x24, 0xb9, 0xa5, 0x53, 0x6b, 0x91, 0x06, 0x95, 0x26, 0xb4,
      0xf6, 0x19, 0x6b, 0x7e, 0x94, 0x75, 0xb4, 0xda, 0x69, 0xe0, 0x1f,
      0x0c, 0x85, 0x57, 0x97, 0xf2, 0x24, 0xcd, 0x73, 0x35, 0xdd, 0xb2,
      0x86, 0xfd, 0x99, 0xb9, 0xb3, 0x2f, 0xfe, 0x33, 0xb5, 0x9a, 0xd4,
      0x24, 0xcc, 0x17, 0x44, 0xf6, 0xeb, 0x59, 0x13, 0x7f, 0x5f, 0xb8,
      0x60, 0x19, 0x32, 0xe8, 0xa8, 0xaf, 0x0a, 0xe9, 0x30
   }
};

int main()
{  /* check 512-bit sha3() digest results match expected */
   size_t size_digest;
   size_t inlen[NUMVECTORS];
   uint8_t digest[NUMVECTORS][DIGESTLEN];
   int j;

   /* calc sizes */
   size_digest = sizeof(digest);

   /* init memory (synchronous) */
   memset(digest, 0, size_digest);

   for (j = 0; j < NUMVECTORS; j++) {
      inlen[j] = strlen(rfc_1321_vectors[j]);
   }

   /* perform bulk hash */
   test_kcu_sha3(rfc_1321_vectors, inlen, MAXVECTORLEN,
      digest, DIGESTLEN, NUMVECTORS);

   /* analyze results */
   for (j = 0; j < NUMVECTORS; j++) {
      ASSERT_CMP(digest[j], expect[j], DIGESTLEN);
   }
}