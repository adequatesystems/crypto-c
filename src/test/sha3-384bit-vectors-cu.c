
/* must be declared before includes */
#ifndef CUDA
   #define CUDA
#endif

#include <stdint.h>
#include "_assert.h"
#include "../sha3.h"

#define NUMVECTORS    7
#define MAXVECTORLEN  81
#define DIGESTLEN     SHA3LEN384

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
      0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d, 0x01, 0x10,
      0x7d, 0x85, 0x2e, 0x4c, 0x24, 0x85, 0xc5, 0x1a, 0x50, 0xaa,
      0xaa, 0x94, 0xfc, 0x61, 0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98,
      0x3a, 0x2a, 0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47,
      0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04
   }, {
      0x18, 0x15, 0xf7, 0x74, 0xf3, 0x20, 0x49, 0x1b, 0x48, 0x56,
      0x9e, 0xfe, 0xc7, 0x94, 0xd2, 0x49, 0xee, 0xb5, 0x9a, 0xae,
      0x46, 0xd2, 0x2b, 0xf7, 0x7d, 0xaf, 0xe2, 0x5c, 0x5e, 0xdc,
      0x28, 0xd7, 0xea, 0x44, 0xf9, 0x3e, 0xe1, 0x23, 0x4a, 0xa8,
      0x8f, 0x61, 0xc9, 0x19, 0x12, 0xa4, 0xcc, 0xd9
   }, {
      0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9, 0x26, 0x45,
      0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d, 0xf9, 0xb4, 0x73, 0xcb,
      0x0f, 0xc0, 0x8c, 0x25, 0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b,
      0xe4, 0xb2, 0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5,
      0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25
   }, {
      0xd9, 0x51, 0x97, 0x09, 0xf4, 0x4a, 0xf7, 0x3e, 0x2c, 0x8e,
      0x29, 0x11, 0x09, 0xa9, 0x79, 0xde, 0x3d, 0x61, 0xdc, 0x02,
      0xbf, 0x69, 0xde, 0xf7, 0xfb, 0xff, 0xdf, 0xff, 0xe6, 0x62,
      0x75, 0x15, 0x13, 0xf1, 0x9a, 0xd5, 0x7e, 0x17, 0xd4, 0xb9,
      0x3b, 0xa1, 0xe4, 0x84, 0xfc, 0x19, 0x80, 0xd5
   }, {
      0xfe, 0xd3, 0x99, 0xd2, 0x21, 0x7a, 0xaf, 0x4c, 0x71, 0x7a,
      0xd0, 0xc5, 0x10, 0x2c, 0x15, 0x58, 0x9e, 0x1c, 0x99, 0x0c,
      0xc2, 0xb9, 0xa5, 0x02, 0x90, 0x56, 0xa7, 0xf7, 0x48, 0x58,
      0x88, 0xd6, 0xab, 0x65, 0xdb, 0x23, 0x70, 0x07, 0x7a, 0x5c,
      0xad, 0xb5, 0x3f, 0xc9, 0x28, 0x0d, 0x27, 0x8f
   }, {
      0xd5, 0xb9, 0x72, 0x30, 0x2f, 0x50, 0x80, 0xd0, 0x83, 0x0e,
      0x0d, 0xe7, 0xb6, 0xb2, 0xcf, 0x38, 0x36, 0x65, 0xa0, 0x08,
      0xf4, 0xc4, 0xf3, 0x86, 0xa6, 0x11, 0x12, 0x65, 0x2c, 0x74,
      0x2d, 0x20, 0xcb, 0x45, 0xaa, 0x51, 0xbd, 0x4f, 0x54, 0x2f,
      0xc7, 0x33, 0xe2, 0x71, 0x9e, 0x99, 0x92, 0x91
   }, {
      0x3c, 0x21, 0x3a, 0x17, 0xf5, 0x14, 0x63, 0x8a, 0xcb, 0x3b,
      0xf1, 0x7f, 0x10, 0x9f, 0x3e, 0x24, 0xc1, 0x6f, 0x9f, 0x14,
      0xf0, 0x85, 0xb5, 0x2a, 0x2f, 0x2b, 0x81, 0xad, 0xc0, 0xdb,
      0x83, 0xdf, 0x1a, 0x58, 0xdb, 0x2c, 0xe0, 0x13, 0x19, 0x1b,
      0x8b, 0xa7, 0x2d, 0x8f, 0xae, 0x7e, 0x2a, 0x5e
   }
};

int main()
{  /* check 384-bit sha3() digest results match expected */
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
