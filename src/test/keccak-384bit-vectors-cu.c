
/* must be declared before includes */
#ifndef CUDA
   #define CUDA
#endif

#include <stdint.h>
#include "_assert.h"
#include "../sha3.h"

#define NUMVECTORS    7
#define MAXVECTORLEN  81
#define DIGESTLEN     KECCAKLEN384

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
      0x2c, 0x23, 0x14, 0x6a, 0x63, 0xa2, 0x9a, 0xcf, 0x99, 0xe7, 0x3b,
      0x88, 0xf8, 0xc2, 0x4e, 0xaa, 0x7d, 0xc6, 0x0a, 0xa7, 0x71, 0x78,
      0x0c, 0xcc, 0x00, 0x6a, 0xfb, 0xfa, 0x8f, 0xe2, 0x47, 0x9b, 0x2d,
      0xd2, 0xb2, 0x13, 0x62, 0x33, 0x74, 0x41, 0xac, 0x12, 0xb5, 0x15,
      0x91, 0x19, 0x57, 0xff
   }, {
      0x85, 0xe9, 0x64, 0xc0, 0x84, 0x3a, 0x7e, 0xe3, 0x2e, 0x6b, 0x58,
      0x89, 0xd5, 0x0e, 0x13, 0x0e, 0x64, 0x85, 0xcf, 0xfc, 0x82, 0x6a,
      0x30, 0x16, 0x7d, 0x1d, 0xc2, 0xb3, 0xa0, 0xcc, 0x79, 0xcb, 0xa3,
      0x03, 0x50, 0x1a, 0x1e, 0xea, 0xba, 0x39, 0x91, 0x5f, 0x13, 0xba,
      0xab, 0x5a, 0xba, 0xcf
   }, {
      0xf7, 0xdf, 0x11, 0x65, 0xf0, 0x33, 0x33, 0x7b, 0xe0, 0x98, 0xe7,
      0xd2, 0x88, 0xad, 0x6a, 0x2f, 0x74, 0x40, 0x9d, 0x7a, 0x60, 0xb4,
      0x9c, 0x36, 0x64, 0x22, 0x18, 0xde, 0x16, 0x1b, 0x1f, 0x99, 0xf8,
      0xc6, 0x81, 0xe4, 0xaf, 0xaf, 0x31, 0xa3, 0x4d, 0xb2, 0x9f, 0xb7,
      0x63, 0xe3, 0xc2, 0x8e
   }, {
      0x8a, 0x37, 0x7d, 0xb0, 0x88, 0xc4, 0x3e, 0x44, 0x04, 0x0a, 0x2b,
      0xfb, 0x26, 0x67, 0x67, 0x04, 0x99, 0x9d, 0x90, 0x52, 0x79, 0x13,
      0xca, 0xbf, 0xf0, 0xa3, 0x48, 0x48, 0x25, 0xda, 0xa5, 0x4d, 0x30,
      0x61, 0xe6, 0x7d, 0xa7, 0xd8, 0x36, 0xa0, 0x80, 0x53, 0x56, 0x96,
      0x2a, 0xf3, 0x10, 0xe8
   }, {
      0xc5, 0xa7, 0x08, 0xec, 0x21, 0x78, 0xd8, 0xc3, 0x98, 0x46, 0x15,
      0x47, 0x43, 0x5e, 0x48, 0x2c, 0xee, 0x0d, 0x85, 0xde, 0x3d, 0x75,
      0xdd, 0xbf, 0xf5, 0x4e, 0x66, 0x06, 0xa7, 0xe9, 0xf9, 0x94, 0xf0,
      0x23, 0xa6, 0x03, 0x3b, 0x2b, 0xf4, 0xc5, 0x16, 0xa5, 0xf7, 0x1f,
      0xc7, 0x47, 0x0d, 0x1a
   }, {
      0x73, 0x77, 0xc5, 0x70, 0x75, 0x06, 0x57, 0x5c, 0x26, 0x93, 0x7f,
      0x3d, 0xf0, 0xd4, 0x4a, 0x77, 0x3f, 0x8c, 0x74, 0x52, 0xc0, 0x74,
      0xee, 0x17, 0x25, 0xc1, 0xab, 0x62, 0xf7, 0x41, 0xf9, 0x50, 0x59,
      0x45, 0x9d, 0x64, 0xca, 0xeb, 0xf3, 0x5a, 0x7c, 0x24, 0x7f, 0xe2,
      0x86, 0x16, 0xca, 0xb6
   }, {
      0xfd, 0x6e, 0x89, 0xcb, 0xe3, 0x27, 0x15, 0x45, 0xf9, 0x4c, 0x3e,
      0x67, 0x86, 0x80, 0x32, 0x60, 0xf9, 0x29, 0xc1, 0x58, 0x9e, 0x30,
      0x91, 0xaf, 0xd5, 0x8c, 0xf3, 0x2e, 0xf5, 0x3a, 0x4f, 0x29, 0xb6,
      0x9c, 0x11, 0x66, 0xcb, 0x29, 0x82, 0xe2, 0xcb, 0x65, 0xcf, 0x5e,
      0xb9, 0x03, 0xe6, 0x69
   }
};

int main()
{  /* check 384-bit keccak() digest results match expected */
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
   test_kcu_keccak(rfc_1321_vectors, inlen, MAXVECTORLEN,
      digest, DIGESTLEN, NUMVECTORS);

   /* analyze results */
   for (j = 0; j < NUMVECTORS; j++) {
      ASSERT_CMP(digest[j], expect[j], DIGESTLEN);
   }
}
